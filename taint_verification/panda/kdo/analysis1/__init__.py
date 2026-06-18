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

pattern = re.compile(r"repro-[0-9a-f]+$")

kdo_label = 1
kdo_taint_addr = None
kdo_callstack = dict()
kdo_allocations = dict()
kdo_taints = dict()
taint_sites = dict()
resched_ctr = 0
analysis = dict()

memcpy_ctr = 0

syscall_ctr = 0
cur_syscall = dict()
syscalls_freq = dict()

cb_enabled = False

expect_prompt="(REPRODUCER DID NOT CRASH|KCSAN|UBSAN|KDO|WARNING|INFO|protection fault|Rebooting in 86400 seconds|~ # )"
expect_prompt="(REPRODUCER DID NOT CRASH|KCSAN|UBSAN|KDO|Rebooting in 86400 seconds|~ # )"
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

def __replay(rootfs, kernel, record, ignored_addresses, func_map, symbol_map,
		sink_call_id, source_call_id, target_addr, cfu_dst, enable_logging):

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

	outfile_file = open('./kllvm_output1', "w+")
	tb_file = open('./kllvm_tb_output1.txt', "w+")

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
	panic_addr = symbol_map.get('panic', None).address

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
	print(f'panic_addr: {hex(panic_addr)}')

	# @panda.cb_after_machine_init
	# def setup(cpu):
	#	 # panda.taint_enable()

	# @panda.cb_before_block_exec
	# def server_bbe(cpu, tb):
	#	 global kdo_label
	#	 # if tb.pc == 0xffffffff87603f7d:
	#	 if tb.pc == 0xffffffff84a9d19a:
	#		 val = panda.arch.get_reg(cpu, "RSI")
	#		 kdo_label += 1
	#		 taint_paddr = panda.virt_to_phys(cpu, val)
	#		 # panda.taint_label_ram(taint_paddr, kdo_label)
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

	def set_taint_virtual_addr(cpu, addr, length, taint_label):
		enable_taint()
		log(f'f: creating taint for: {hex(addr)}, label {taint_label}', file=outfile_file)
		backtrace(cpu)
		for offset in range(length):
			taint_paddr = panda.virt_to_phys(cpu, addr+offset)
			panda.taint_label_ram(taint_paddr, taint_label)

	def set_taint_virtual_addr_custom(cpu, addr, length):
		enable_taint()
		taint_label = addr & 0xffffffff
		log(f'f: creating taint for: {hex(addr)}, label {taint_label}', file=outfile_file)
		backtrace(cpu)
		for offset in range(length):
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


	def on_call(cpu, addr):
		global kdo_allocations
		global kdo_callstack
		global kdo_label
		global kdo_taint_addr
		global cur_syscall
		global resched_ctr
		global analysis
		global kdo_taints
		global taint_sites
		global memcpy_ctr

		if addr == panic_addr:
			analysis = dict()
			analysis['memcpy_ctr'] = memcpy_ctr
			log(f'PANIC!!!!', file=outfile_file)
			print("Terminating analysis...")
			panda.end_analysis()

# 		if addr == kdo_copy_from_user_addr:
# 			cfu_id = panda.arch.get_arg(cpu, 0)
# 			dest_ptr = panda.arch.get_arg(cpu, 1)
# 			length = panda.arch.get_arg(cpu, 2)
# 			kdo_label += 1

			# ctr = 0
			# if cfu_id in taint_sites:
			# 	ctr = taint_sites[cfu_id]
			# 	ctr += 1

			# taint_sites[cfu_id] = ctr

			# kdo_taints[kdo_label] = {
			# 	"cfu_id": cfu_id,
			# 	"backtrace":    panda.callstack_callers(20, cpu),
			# 	"ctr": ctr,
			# }

			# set_taint_virtual_addr(cpu, dest_ptr, length, kdo_label)
			# log(f'f: kdo_copy_from_user, dest_ptr: {hex(dest_ptr)}, length: {length}, cfu_id: {cfu_id}, pc: {hex(get_retval(cpu))}', file=outfile_file)

		elif addr == __kdo_asan_memcpy_addr or addr == __kdo_asan_memmove_addr:
			dest =	 panda.arch.get_arg(cpu, 0)
			src =	  panda.arch.get_arg(cpu, 1)
			size =	 panda.arch.get_arg(cpu, 2)
			call_id =  panda.arch.get_arg(cpu, 3)

			if call_id == sink_call_id:

				## # bail if it's not a reproducer
				## proc = panda.plugins['osi'].get_current_process(cpu)
				## if proc == panda.ffi.NULL:
				## 	return
				pname = panda.get_process_name(cpu)
				if not pattern.search(pname): return

				memcpy_ctr += 1

				log(f'f: __kdo_asan_memcpy, dest: {hex(dest)}, src: {hex(src)}, length: {size}, call_id: {call_id}, pc: {hex(get_retval(cpu))}', file=outfile_file)

				### ### taint_info = []

				### ### for offset in range(size):
				### ### 	taint = get_taint_virtual_addr(cpu, src+offset)

				### ### 	log(f'taint(src: {hex(src+offset)}): kasan(src): {get_kasan_shadow_byte(cpu, src+offset)}', file=outfile_file)

				### ### 	taint_data = dict()
				### ### 	taint_data["off"] = offset

				### ### 	if taint is None:
				### ### 		taint_data["err"] = "no_taint"
				### ### 	else:
				### ### 		labels = taint.get_labels()
				### ### 		log(f'labels on soruce ptr are {labels}', file=outfile_file)

				### ### 		taintz = []
				### ### 		for label in labels:
				### ### 			log(f'label is {label}', file=outfile_file)

				### ### 			log(f'taint data is: {json.dumps(kdo_taints[label], indent=2)}', file=outfile_file)
				### ### 			taintz.append(kdo_taints[label])

				### ### 		taint_data["data"] = taintz

				### ### 	taint_info.append(taint_data)

				### ### analysis["taint_src_ext"] = taint_info

				### ### # # Extracting label from taint
				### ### # label = None
				### ### # for idx, byte_taint in enumerate(taint):
				### ### # 	if byte_taint is None:
				### ### # 		log(f'none byte taint', file=outfile_file)
				### ### # 		continue

				### ### # 	labels = byte_taint.get_labels()
				### ### # 	log(f'labels on destination ptr are {labels}', file=outfile_file)
				### ### # 	if len(labels) > 1:
				### ### # 		log('WARNING: multiple labels encoutered!!!!!', file=outfile_file)
				### ### # 		analysis['err'] = 'multilabel'
				### ### # 	if len(labels) > 0:
				### ### # 		label = labels[0]
				### ### # 	break

				### ### # log(f'label is {label}', file=outfile_file)
				### ### # if not label:
				### ### # 	analysis['err'] = 'nolabel'

				### ### #########################################################################
				### ### #########################################################################
				### ### #########################################################################

				### ### # tq = get_taint_virtual_addr(cpu, src)
				### ### # if tq is not None:
				### ### # 	labels = tq.get_labels()
				### ### # 	log(f'labels on soruce ptr are {labels}', file=outfile_file)
				### ### # 	src_label = None
				### ### # 	if len(labels) > 1:
				### ### # 		log('WARNING: multiple labels encoutered!!!!!', file=outfile_file)
				### ### # 	if len(labels) > 0:
				### ### # 		src_label = labels[0]

				### ### # 	log(f'src label is {src_label}', file=outfile_file)

				### ### # 	if src_label in kdo_taints:
				### ### # 		log(f'taint data is: {json.dumps(kdo_taints[src_label], indent=2)}', file=outfile_file)
				### ### # 		analysis['taint_src'] = kdo_taints[src_label]
				### ### # else:
				### ### # 	log(f'empty label on src ptr', file=outfile_file)

				### ### #########################################################################
				### ### #########################################################################
				### ### #########################################################################

				### ### print("Terminating analysis...")
				### ### panda.end_analysis()

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		# Read the filename string from memory
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)  # Read up to 256 bytes
		except ValueError:
			return
		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8')  # Decode the null-terminated string

		print(f"execve enter: {fname}")

		d = panda.ppp("callstack_instr", "on_call")
		d(on_call)

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

	print(f'kdo_label: {kdo_label}')

	end = time.time()
	print(f'time: {end - start}')

	global analysis
	analysis["replay_time"] = end - start
	with open('./analysis1.json', "w") as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel,
		sink_call_id, source_call_id=None, target_addr=None, cfu_dst=None, enable_logging=True, record='record'):

	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			additional_args=[sink_call_id, source_call_id, target_addr, cfu_dst, enable_logging])

def parse_reports_json(reports_path, reports_json):
	kdo_bugs = reports_json

	repros = []

	for kdo_bug in kdo_bugs:
		crash_dir = os.path.join(reports_path, kdo_bug['id']) # f'{reports_path}/{kdo_bug["crash_dir"]}'
		if not os.path.isdir(crash_dir):
			crash_dir = os.path.join(reports_path, kdo_bug['id']+".old")
			if not os.path.isdir(crash_dir):
				print(f"WARNING: could not find directory for {kdo_bug['id']}")
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
