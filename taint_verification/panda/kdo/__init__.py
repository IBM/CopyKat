#!/usr/bin/env python3

from pandare import Panda
from pandare import panda_expect

import rrr
from rrr import arch, mem, expect_prompt, extra_qemu_machine_args, config

import os
import time
import importlib
import shutil
import stat
import json
import traceback
import re
import faulthandler
import tempfile

pattern = re.compile(r"repro-[a-z_]+$")

kdo_label_nr = 1
kdo_taint_addr = None
kdo_callstack = dict()
kdo_allocations = dict()
kdo_taints = dict()
resched_ctr = 0
analysis = dict()
memcpy_ctr = 1

syscall_ctr = 0
cur_syscall = dict()
syscalls_freq = dict()

set_storedonheap_ctr = dict()

cb_enabled = False

expect_prompt="(REPRODUCER DID NOT CRASH|KCSAN|UBSAN|KDO|WARNING|INFO|protection fault|Rebooting in 86400 seconds|~ # )"
expect_prompt="(REPRODUCER DID NOT CRASH|KCSAN|UBSAN|KDO|Rebooting in 86400 seconds|~ # )"
expect_prompt="(REPRODUCER DID NOT CRASH|KCSAN|UBSAN|Rebooting in 86400 seconds|KDO:\s*([^()]*)\s*\(([^)]*)\)|~ # )"
init_code = f"""#!/bin/sh

# Mount various important file systems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /run
mount -t tmpfs none /tmp
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t securityfs none /sys/kernel/security
mount -t configfs none /sys/kernel/config
mount -t binfmt_misc none /proc/sys/fs/binfmt_misc
mount -t fusectl none /sys/fs/fuse/connections
mount -t pstore none /sys/fs/pstore
mount -t bpf none /sys/fs/bpf
mount -t tracefs none /sys/kernel/tracing
mkdir -p /dev/pts /dev/shm
mount -t devpts none /dev/pts
mount -t tmpfs none /dev/shm

# disable runtime completely
# echo '/' > /proc/kdo_fault_filter

# disable taint functions
# echo '^' > /proc/kdo_fault_filter

# disable kasan checks
echo 'a' > /proc/kdo_fault_filter
# disable kcov functions
echo 'k' > /proc/kdo_fault_filter

# Use the serial line to notify our wrapper of boot completion
echo {config["ready_serial_signal"]}

## # Wait for an enter key before running the reproducer
## read
##
## # Run the reproducer
## /repros/repro-$REPLY
##
## # If we're here, it didn't crash the kernel. Write something and wait
## echo REPRODUCER DID NOT CRASH
## read
##
## # If we end up here, someone is debugging manually, drop them into a shell
setsid /sbin/getty -l /bin/sh -n 115200 ttyS0
"""

conf = config
conf["expect_prompt"] = expect_prompt
conf["init_code"] = init_code

def update_config():
	rrr.update_config(conf)

repro_crashed = True
last_prompt = ""
def __record(rootfs, output, timeout, repro_id):
	panda = Panda(arch=config["arch"], mem=config["mem"], expect_prompt=config["expect_prompt"], qcow=rootfs.path,
			extra_args=config["extra_qemu_machine_args"])
	panda.serial_console.set_logging('panda_logging.txt')

	@panda.queue_blocking
	def drive():
		global repro_crashed
		global last_prompt

		print("drive starts")
		panda.revert_sync("root")
		print("Starting record...")
		panda.run_monitor_cmd(f"begin_record {output}")

		# panda.serial_console.sendline(str.encode(repro_id))
		panda.serial_console.expect(timeout=timeout)
		# print(panda.serial_console.get_partial())
		panda.run_serial_cmd("/repros/repro-" + repro_id, timeout=timeout)
		repro_crashed = True

		if re.search('~ # ', panda.serial_console.last_prompt):
			repro_crashed = False

		last_prompt = panda.serial_console.last_prompt

		panda.run_monitor_cmd("end_record")
		print("Finished record")
		panda.end_analysis()
		print("drive returns")

	try:
		panda.run()
	except panda_expect.TimeoutExpired:
		with open('panda_logging.txt', 'a') as f:
			f.write("KDO_PANDA_HAS_TIMED_OUT")

	global last_prompt
	global repro_crashed
	print(f'__record exits: last prompt {last_prompt}, repro crashed {repro_crashed}')

	if not repro_crashed:
		with open('panda_logging.txt', 'a') as f:
			f.write("\nREPRODUCER DID NOT CRAS")

def record(kernel, rootfs, timeout, repro_id, output="record"):
	return rrr.record(kernel, rootfs, timeout, __record, output=output, additional_args=[repro_id])

# kdo.replay(rootfs, kernel, sink_call_id=callid, target_addr=[target_addr], ref_memcpy_ctr=ctr)
#	rrr.replay(rootfs, kernel, record, __replay,
#			additional_args=[sink_call_id, target_addr, ref_memcpy_ctr, enable_logging])
def __replay(rootfs, kernel, record, ignored_addresses, func_map, symbol_map,
		sink_call_id, target_addr, ref_memcpy_ctr, enable_logging):

	crashlogf = open(tempfile.NamedTemporaryFile(prefix="crash_info_", suffix=".log", dir=None, delete=False).name, "w")
	faulthandler.enable(file=crashlogf)

	start = time.time()
	panda = Panda(arch=config["arch"], mem=config["mem"], expect_prompt=config["expect_prompt"], qcow=rootfs.path,
				  extra_args=config["extra_qemu_machine_args"], os_version="linux-64-linux:1.0")

	panda.load_plugin("taint2", args={
		"opt": True,
		# "no_tp": True,
	})

	# Load Panda's OSI manually to provide it our custom kernel info file
	panda.load_plugin("osi", args={"disable-autoload": True})
	panda.load_plugin("osi_linux", args={
		"kconf_file": kernel.info_path, "kconf_group": "linux:1.0:64"
	})

	# Use OSI to track function calls and returns on a per-thread basis
	# panda.load_plugin("callstack_instr", args={"stack_type": "threaded"})
	panda.load_plugin("callstack_instr")

	outfile_file = open('./kllvm_output', "w+")
	tb_file = open('./kllvm_tb_output.txt', "w+")

	kdo_copy_from_user_addr = symbol_map.get('kdo_copy_from_user', None).address
	kdo_kasan_report_addr = symbol_map.get('kdo_kasan_report', None).address
	kdo_store_hook_addr = symbol_map.get('kdo_store_hook', None).address
	__kdo_asan_memmove_addr = symbol_map.get('__kdo_asan_memmove', None).address
	__kdo_asan_memcpy_addr = symbol_map.get('__kdo_asan_memcpy', None).address
	kdo_taint_val_stored_on_heap_addr = symbol_map.get('kdo_taint_val_stored_on_heap', None).address
	kdo_set_storedonheap_addr = symbol_map.get('kdo_set_storedonheap', None).address
	propagate_taint_addr = symbol_map.get('propagate_taint', None).address
	kdo_post_store_hook_addr = symbol_map.get('kdo_post_store_hook', None).address
	kmem_cache_alloc_addr = symbol_map.get('kmem_cache_alloc', None).address
	kmem_cache_alloc_lru_addr = symbol_map.get('kmem_cache_alloc_lru', None).address
	kmem_cache_alloc_node_addr = symbol_map.get('kmem_cache_alloc_node', None).address
	kmalloc_addr = symbol_map.get('__kmalloc', None).address
	__kasan_kmalloc_addr = symbol_map.get('__kasan_kmalloc', None).address
	__kasan_krealloc_addr = symbol_map.get('__kasan_krealloc', None).address
	__kasan_slab_alloc_addr = symbol_map.get('__kasan_slab_alloc', None).address
	do_syscall_64_addr = symbol_map.get('do_syscall_64', None).address
	__cond_resched_addr = symbol_map.get('__cond_resched', None).address

	print(f'kdo_copy_from_user_addr: {hex(kdo_copy_from_user_addr)}')
	print(f'kdo_store_hook_addr: {hex(kdo_store_hook_addr)}')
	print(f'__kdo_asan_memmove_addr: {hex(__kdo_asan_memmove_addr)}')
	print(f'__kdo_asan_memcpy_addr: {hex(__kdo_asan_memcpy_addr)}')
	print(f'kdo_taint_val_stored_on_heap_addr: {hex(kdo_taint_val_stored_on_heap_addr)}')
	print(f'kdo_set_storedonheap_addr: {hex(kdo_set_storedonheap_addr)}')
	print(f'propagate_taint_addr: {hex(propagate_taint_addr)}')
	print(f'kdo_post_store_hook_addr: {hex(kdo_post_store_hook_addr)}')
	print(f'kmem_cache_alloc_addr: {hex(kmem_cache_alloc_addr)}')
	print(f'kmem_cache_alloc_lru_addr: {hex(kmem_cache_alloc_lru_addr)}')
	print(f'kmem_cache_alloc_node_addr: {hex(kmem_cache_alloc_node_addr)}')
	print(f'kmalloc_addr: {hex(kmalloc_addr)}')
	print(f'__kasan_kmalloc_addr: {hex(__kasan_kmalloc_addr)}')
	print(f'__kasan_krealloc_addr: {hex(__kasan_krealloc_addr)}')
	print(f'__kasan_slab_alloc_addr: {hex(__kasan_slab_alloc_addr)}')
	print(f'do_syscall_64_addr: {hex(do_syscall_64_addr)}')
	print(f'__cond_resched_addr: {hex(__cond_resched_addr)}')

	# @panda.cb_after_machine_init
	# def setup(cpu):
	#	 # panda.taint_enable()

	# @panda.cb_before_block_exec
	# def server_bbe(cpu, tb):
	#	 global kdo_label_nr
	#	 # if tb.pc == 0xffffffff87603f7d:
	#	 if tb.pc == 0xffffffff84a9d19a:
	#		 val = panda.arch.get_reg(cpu, "RSI")
	#		 kdo_label_nr += 1
	#		 taint_paddr = panda.virt_to_phys(cpu, val)
	#		 # panda.taint_label_ram(taint_paddr, kdo_label_nr)
	#		 print(f'pc: {hex(tb.pc)}, taint_paddr: {hex(taint_paddr)}', file=tb_file)

	def backtrace(cpu):
		cc = panda.callstack_callers(20, cpu)
		log(f'\tbacktrace:', file=outfile_file)
		for ccc in cc:
			log(f'\t: {hex(ccc)}', file=outfile_file)

	def log(s, file):
		if enable_logging:
			print(s, file=file)

	def enable_taint():
		if not panda.taint_enabled():
			panda.taint_enable()

	def set_taint_virtual_addr(cpu, addr, len, taint_label):
		enable_taint()
		log(f'f: creating taint for: {hex(addr)}, label {taint_label}', file=outfile_file)
		backtrace(cpu)
		for offset in range(len):
			taint_paddr = panda.virt_to_phys(cpu, addr+offset)
			panda.taint_label_ram(taint_paddr, taint_label)

	def set_taint_virtual_addr_custom(cpu, addr, len):
		enable_taint()
		taint_label = addr & 0xffffffff
		log(f'f: creating taint for: {hex(addr)}, label {taint_label}', file=outfile_file)
		backtrace(cpu)
		for offset in range(len):
			taint_paddr = panda.virt_to_phys(cpu, addr+offset)
			panda.taint_label_ram(taint_paddr, taint_label)

	def get_taint_virtual_addr(cpu, addr):
		if not panda.taint_enabled():
			return None
		taint_paddr = panda.virt_to_phys(cpu, addr)
		return panda.taint_get_ram(taint_paddr)

	def get_taint_reg(cpu, reg):
		if not panda.taint_enabled():
			return [None]
		reg_num = panda.arch.registers[reg]
		return panda.taint_get_reg(reg_num)

	def get_kasan_shadow_byte(cpu, addr):
		shadow_addr = (addr >> 3) + 0xdffffc0000000000
		return panda.virtual_memory_read(cpu, shadow_addr, 0x1)

	def get_retval(cpu):
		return panda.arch.get_return_address(cpu)

	# @panda.cb_virt_mem_after_write()
	# def virt_mem_after_write(cpu, pc, addr, size, buf):
	#	 global kdo_taint_addr
	#
	#	 if kdo_taint_addr and kdo_taint_addr == addr:
	#		 set_taint_virtual_addr_custom(cpu, kdo_taint_addr, 8)
	#		 kdo_taint_addr = None

	# @panda.ppp("taint2", "on_taint_prop")
	# def on_taint_prop(src, dst, size):
	#	 if src.typ == 1:
	#		 print(f'on_taint_prop: src.typ: {hex(src.val)}, dst: {dst.typ}, size: {size}')


	def all_sysenter(cpu, pc, callno):
		global syscall_ctr
		global cur_syscall
		global syscalls_freq
		global cb_enabled

		# bail if it's not a reproducer
		if not is_repro(panda, cpu): return
	#	proc = panda.plugins['osi'].get_current_process(cpu)
	#	if proc == panda.ffi.NULL:
	#		return
	#	pname = panda.ffi.string(proc.name).decode()
	#	if not pattern.search(pname): return

		# start callbacks
		if not cb_enabled:
			d2 = panda.ppp("callstack_instr", "on_ret")
			d2(on_ret)

			d3 = panda.ppp("callstack_instr", "on_call")
			d3(on_call)

			cb_enabled = True
			print("Enabling callbacks...")

		# update stats
		syscall_ctr += 1
		backtrace = panda.callstack_callers(20, cpu)
		backtrace_hash = 0
		if len(backtrace) > 0:
			backtrace_hash = backtrace[0]

		if backtrace_hash not in syscalls_freq:
			syscalls_freq[backtrace_hash] = 0

		syscalls_freq[backtrace_hash] += 1

		# record data
		cur_syscall.clear()
		cur_syscall['n'] = callno
		cur_syscall['backtrace'] = backtrace
		cur_syscall['global_ctr'] = syscall_ctr
		cur_syscall['syscall_ctr'] = syscalls_freq[backtrace_hash]
		cur_syscall['rdi'] = panda.arch.get_reg(cpu, "RDI")
		cur_syscall['rsi'] = panda.arch.get_reg(cpu, "RSI")
		cur_syscall['rdx'] = panda.arch.get_reg(cpu, "RDX")
		cur_syscall['r10'] = panda.arch.get_reg(cpu, "R10")
		cur_syscall['r8'] = panda.arch.get_reg(cpu, "R8")
		cur_syscall['r9'] = panda.arch.get_reg(cpu, "R9")

	def on_ret(cpu, addr):
		global kdo_callstack
		global kdo_allocations
		global resched_ctr
		global cur_syscall

		if addr == kmem_cache_alloc_addr or addr == kmem_cache_alloc_node_addr or addr == kmem_cache_alloc_lru_addr or addr == __kasan_kmalloc_addr or addr == __kasan_slab_alloc_addr:
			ptr = panda.arch.get_return_value(cpu)
			rsp = panda.arch.get_reg(cpu, "RSP")

			cachep = kdo_callstack[rsp-8]["arg"]
			size = panda.virtual_memory_read(cpu, cachep+28, 0x4, fmt="int")		# object_size 28
			cachename_p = panda.virtual_memory_read(cpu, cachep+96, 8, fmt="int")   # name 96
			cachename = panda.virtual_memory_read(cpu, cachename_p, 40, fmt="str")
			del kdo_callstack[rsp-8]

			kdo_allocations[ptr] = {
				"cache": str(cachename),
				"size": size,
				"backtrace": panda.callstack_callers(20, cpu),
				"resched_ctr": resched_ctr,
				"instr_ctr": panda.rr_get_guest_instr_count(),
				"syscall": cur_syscall.copy(),
			}

		elif addr == kmalloc_addr or addr == __kasan_krealloc_addr:
			ptr = panda.arch.get_return_value(cpu)
			rsp = panda.arch.get_reg(cpu, "RSP")

			size = kdo_callstack[rsp-8]["arg"]
			del kdo_callstack[rsp-8]

			kdo_allocations[ptr] = {
				"cache": "_kmalloc_",
				"size": size,
				"backtrace": panda.callstack_callers(20, cpu),
				"syscall": cur_syscall.copy(),
				"resched_ctr": resched_ctr,
				"instr_ctr": panda.rr_get_guest_instr_count(),
			}

	def on_call(cpu, addr):
		global kdo_taints
		global kdo_allocations
		global kdo_callstack
		global kdo_label_nr
		global kdo_taint_addr
		global cur_syscall
		global resched_ctr
		global analysis
		global set_storedonheap_ctr
		global memcpy_ctr

		if addr == kmem_cache_alloc_addr:
			cachep = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": cachep, "type": "kmem_cache_alloc"}

		elif addr == kmem_cache_alloc_node_addr:
			cachep = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": cachep, "type": "kmem_cache_alloc_node"}

		elif addr == kmem_cache_alloc_lru_addr:
			cachep = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": cachep, "type": "kmem_cache_alloc_lru"}

		elif addr == kmalloc_addr:
			size = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": size, "type": "kmalloc"}

		elif addr == __kasan_kmalloc_addr:
			cachep = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": cachep, "type": "__kasan_kmalloc"}

		elif addr == __kasan_slab_alloc_addr:
			cachep = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": cachep, "type": "__kasan_slab_alloc"}

		elif addr == __kasan_krealloc_addr:
			size = panda.arch.get_arg(cpu, 0)
			rsp = panda.arch.get_reg(cpu, "RSP")
			kdo_callstack[rsp] = {"arg": size, "type": "__kasan_krealloc"}

		##  elif addr == __kdo_asan_memmove_addr:
		##	  dest =	 panda.arch.get_arg(cpu, 0)
		##	  src =	  panda.arch.get_arg(cpu, 1)
		##	  len =	  panda.arch.get_arg(cpu, 2)
		##	  call_id =  panda.arch.get_arg(cpu, 3)

		##	  # log(f'f: __kdo_asan_memmove, dest: {hex(dest)}, src: {hex(src)}, len: {len}, call_id: {call_id}, pc: {hex(get_retval(cpu))}', file=outfile_file)

		elif addr == __kdo_asan_memcpy_addr or addr == __kdo_asan_memmove_addr:
			dest =	 panda.arch.get_arg(cpu, 0)
			src =	  panda.arch.get_arg(cpu, 1)
			size =	 panda.arch.get_arg(cpu, 2)
			call_id =  panda.arch.get_arg(cpu, 3)

			if call_id == sink_call_id:
				# bail if it's not a reproducer
				if not is_repro(panda, cpu): return

				log(f'f: __kdo_asan_memcpy, ctr {memcpy_ctr}, ref_ctr {ref_memcpy_ctr}, dest: {hex(dest)}, src: {hex(src)}, len: {size}, call_id: {call_id}, pc: {hex(get_retval(cpu))} syscall_ctr {syscall_ctr} resched_ctr {resched_ctr} instr_ctr {panda.rr_get_guest_instr_count()}', file=outfile_file)

				# bail if it's not the right time
				if memcpy_ctr != ref_memcpy_ctr:
					memcpy_ctr += 1
					return

				analysis = dict()

				taint = get_taint_reg(cpu, 'RDI')
				analysis['sink'] = {
					'instr_ctr':	panda.rr_get_guest_instr_count(),
					"syscall": cur_syscall.copy(),
					'resched_ctr':  resched_ctr,
					'call_id':	  call_id,
					"backtrace":	panda.callstack_callers(20, cpu),
					'dest':		 dest,
					'src':		  src,
					'len':		  size,
				}

				# Extracting label from taint
				label = None
				for idx, byte_taint in enumerate(taint):
					if byte_taint is None:
						log(f'none byte taint', file=outfile_file)
						continue

					labels = byte_taint.get_labels()
					log(f'labels on destination ptr are {labels}', file=outfile_file)
					if len(labels) > 1:
						log('WARNING: multiple labels encoutered!!!!!', file=outfile_file)
						analysis['err'] = 'multilabel'
					if len(labels) > 0:
						label = labels[0]
					break

				log(f'label is {label}', file=outfile_file)
				if not label:
					analysis['err'] = 'nolabel'

				# target_obj is the object that stores the pointer we can corrupt
				# we print the taint data which includes the backtrace of where the
				# destination pointer is stored in the target object
				target_obj = None
				if label in kdo_taints and "dst_ptr" in kdo_taints[label]:
					target_obj = kdo_taints[label]["dst_ptr"]
					log(f'taint data is: {json.dumps(kdo_taints[label], indent=2)}', file=outfile_file)
					analysis['ptr_ass'] = kdo_taints[label]

				if target_obj:
					log(f'target obj is {hex(target_obj)}', file=outfile_file)

				# Here we get allocation data for the target object and for the destination pointer
				for ptr in kdo_allocations:
					allocation = kdo_allocations[ptr]
					sz = allocation["size"]
					if dest - ptr >= 0 and dest - ptr < sz:
						log(f'allocation for dest ptr: {json.dumps(allocation, indent=2)}', file=outfile_file)
						analysis['dst_ptr_alloc'] = allocation
					if target_obj:
						if target_obj - ptr >= 0 and target_obj - ptr < sz:
							log(f'allocation for target obj: {json.dumps(allocation, indent=2)}', file=outfile_file)
							analysis['target_obj_alloc'] = allocation
							analysis['target_obj_alloc']['ptr'] = ptr

				# log(f'allocations: {json.dumps(kdo_allocations, indent=2)}', file=outfile_file)


				# for offset in range(size):
				#	 log(f'src:  {hex(src+offset)}', file=outfile_file)
				#	 log(f'taint(src):  {get_taint_virtual_addr(cpu, src+offset)}, kasan(src): {get_kasan_shadow_byte(cpu, src+offset)}',
				#		 file=outfile_file)
				#	 log(f'dest: {hex(dest+offset)}', file=outfile_file)
				#	 log(f'taint(dest): {get_taint_virtual_addr(cpu, dest+offset)}, kasan(dst): {get_kasan_shadow_byte(cpu, dest+offset)}',
				#		 file=outfile_file)

				print("Terminating analysis...")
				panda.end_analysis()

		elif addr == kdo_store_hook_addr:
			# void *dstP, void *val, void *srcP, uint64_t call_id
			dstP =	panda.arch.get_arg(cpu, 0)
			val =	 panda.arch.get_arg(cpu, 1)
			srcP =	panda.arch.get_arg(cpu, 2)
			call_id = panda.arch.get_arg(cpu, 3)

			# bail if it's not a reproducer
			if not is_repro(panda, cpu): return

			if call_id not in set_storedonheap_ctr:
				set_storedonheap_ctr[call_id] = 0
			else:
				set_storedonheap_ctr[call_id] += 1

		elif addr == kdo_set_storedonheap_addr:
			shadow =  panda.arch.get_arg(cpu, 0)
			val =	 panda.arch.get_arg(cpu, 1)
			dstP =	panda.arch.get_arg(cpu, 2)
			call_id = panda.arch.get_arg(cpu, 3)

			# bail if it's not a reproducer
			if not is_repro(panda, cpu): return

			if target_addr:
				for addr in target_addr:
					delta = addr - val

					if delta >= 0 and delta < 8:
						kdo_taint_addr = dstP
						taint = get_taint_virtual_addr(cpu, addr)
						log(f'f: tainting via addr on {hex(addr)}, existing taint {taint}', file=outfile_file)

						log(f'f: kdo_set_storedonheap, val: {hex(val)}[{get_kasan_shadow_byte(cpu, val)}], dstP: {hex(dstP)}[{get_kasan_shadow_byte(cpu, dstP)}], call_id: {call_id}, pc: {hex(get_retval(cpu))}', file=outfile_file)

						d = panda.ppp("callstack_instr", "on_call")
						d(on_call_post_hook)
						print("Enabling on_call_post_hook")

	def on_call_post_hook(cpu, addr):
		global kdo_taints
		global kdo_allocations
		global kdo_callstack
		global kdo_label_nr
		global kdo_taint_addr
		global cur_syscall
		global resched_ctr
		global analysis
		global set_storedonheap_ctr

		if kdo_taint_addr and addr == kdo_post_store_hook_addr:
			dest_ptr = panda.arch.get_arg(cpu, 0)
			val =	  panda.arch.get_arg(cpu, 1)
			src_ptr =  panda.arch.get_arg(cpu, 2)
			call_id =  panda.arch.get_arg(cpu, 3)

			if kdo_taint_addr == dest_ptr:
				log(f'f: kdo_post_store_hook, dest_ptr: {hex(dest_ptr)}, val: {hex(val)}, src_ptr: {hex(src_ptr)}, call_id: {call_id}, pc: {hex(get_retval(cpu))}', file=outfile_file)
				set_taint_virtual_addr_custom(cpu, kdo_taint_addr, 8)

				taint_label = kdo_taint_addr & 0xffffffff
				kdo_taints[taint_label] = {
					"dst_ptr": dest_ptr,
					"backtrace": panda.callstack_callers(20, cpu),
					"syscall": cur_syscall.copy(),
					"resched_ctr": resched_ctr,
					"instr_ctr": panda.rr_get_guest_instr_count(),
					"call_id": call_id,
					"ctr": set_storedonheap_ctr[call_id],
				}

				kdo_taint_addr = None

				panda.disable_ppp("on_call_post_hook")

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		# Read the filename string from memory
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)  # Read up to 256 bytes
		except:
			print("would break on execve...")
			return

		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8')  # Decode the null-terminated string

		print(f"execve enter: {fname}")

		d1 = panda.ppp("syscalls2", "on_all_sys_enter")
		d1(all_sysenter)

		panda.disable_ppp("on_sys_execve_enter")

	print('replay start')

	# Start the Panda replay
	try:
		panda.run_replay(record)
	except Exception:
		print("caught exception")
		print(traceback.format_exc())

	outfile_file.close()
	tb_file.close()
	print('replay done!')

	print(f'kdo_label_nr: {kdo_label_nr}')

	end = time.time()
	print(f'time: {end - start}')

	global analysis
	analysis["replay_time"] = end - start
	with open('./analysis.json', "w") as f:
		f.write(json.dumps(analysis, indent=2))

from cffi import FFI

ffi = FFI()
libc = ffi.dlopen("/lib/x86_64-linux-gnu/libc.so.6")
ffi.cdef("void free(void *);")

def is_repro(panda, cpu):
	rv = False
	proc = panda.plugins['osi'].get_current_process(cpu)
	if proc == panda.ffi.NULL:
		rv = False
	else:
		pname = panda.ffi.string(proc.name).decode()
		if not pattern.search(pname): rv = False
		else: rv = True

	if proc != panda.ffi.NULL:
		if proc.name != panda.ffi.NULL:
			libc.free(proc.name)

		if proc.pages != panda.ffi.NULL:
			libc.free(proc.pages)

		libc.free(proc)

	return rv

# kdo.replay(rootfs, kernel, sink_call_id=callid, target_addr=[target_addr], ref_memcpy_ctr=ctr)
def replay(rootfs, kernel,
		sink_call_id, target_addr=None, ref_memcpy_ctr=-1, enable_logging=True, record='record'):

	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			additional_args=[sink_call_id, target_addr, ref_memcpy_ctr, enable_logging])

def parse_reports_json(reports_path, reports_json):
	kdo_bugs = reports_json

	repros = []

	for kdo_bug in kdo_bugs:
		crash_dir = os.path.join(reports_path, kdo_bug['id']) # f'{reports_path}/{kdo_bug["crash_dir"]}'
		print(f'crash dir is {crash_dir}')
		if not os.path.isdir(crash_dir):
			print(f"WARNING: could not find directory {crash_dir} for {kdo_bug['id']}")
			crash_dir = os.path.join(reports_path, kdo_bug['id']+".old")
			if not os.path.isdir(crash_dir):
				print(f"WARNING: could not find directory {crash_dir} for {kdo_bug['id']}")
				continue

		repro_id = kdo_bug['id'] # os.path.basename(crash_dir)
		repro_path = f'{crash_dir}/repro'
		call_id = kdo_bug['call_id']

		if os.path.isfile(repro_path):
			st = "memcpy"
			if 'store_type' in kdo_bug:
				st = kdo_bug['store_type']
			repros.append({"path": repro_path, "id": repro_id, "call_id": call_id, "fault_type": st})

	return repros

def copy_repros_rootfs(rootfs_path, repros):
	rootfs_repros_path = "rootfs/repros"
	if not os.path.isdir(rootfs_path):
		os.mkdir(rootfs_path)
	if not os.path.isdir(rootfs_repros_path):
		os.mkdir(rootfs_repros_path)

	# copy in all repros
	for repro in repros:
		repro_path = repro['path']
		repro_id = repro['id']

		rootfs_repro_path = os.path.join(rootfs_path, f"repros/repro-{repro_id}")
		shutil.copyfile(repro_path, rootfs_repro_path)
		mode = os.stat(rootfs_repro_path).st_mode
		os.chmod(rootfs_repro_path, mode | stat.S_IEXEC)
