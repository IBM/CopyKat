#!/usr/bin/env -S python3 -u

import argparse
import json
import os
import re
import shutil
import sys

import rrr
from rrr import Stimulus, Rootfs, Kernel, config
import kdo
import time
import pathlib

def run_repro(repro_id, sink_call_id, rootfs, kernel):
	kdo.record(kernel, rootfs, repro_id)

	record_logging = []
	with open('/root/out/panda_logging.txt', 'r') as f:
		lines = f.readlines()
		if len(lines) > 0:
			record_logging = lines[-1].split("', '")

	r = re.compile('^.*Write of size (?P<size>.*) at addr (?P<addr>.*) by task.*$')
	addrs = [m.groupdict() for m in (r.match(line) for line in record_logging) if m]

	if len(addrs) == 0:
		print("COULD NOT FIND DST ADDR")
		return

	target_addr = int(addrs[0]['addr'], 16)
	kdo.replay(rootfs, kernel, sink_call_id=sink_call_id, target_addr=target_addr)

	shutil.copy2('/root/out/panda_logging.txt', f'/root/out/panda_logging-{repro_id}.txt')
	shutil.copy2('/root/out/kllvm_output', f'/root/out/kllvm_output-{repro_id}')
	shutil.copy2('/root/out/record-rr-nondet.log', f'/root/out/record-rr-nondet-{repro_id}.log')


def main() -> None:
	opts = argparse.ArgumentParser(
			description='Run all the repros with panda syz-rrr')
	opts.add_argument('--reports-file', type=argparse.FileType('r'), required=True,
			help='reports json exported by extract-info.py')
	opts.add_argument('--record-file', type=argparse.FileType('r'), required=True,
			help='output from initial recording')
	opts.add_argument('--path', type=pathlib.Path, required=True,
		help='Path to the reports')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	args = opts.parse_args()

	reports_path = args.path
	kdo.update_config()

	os.chdir("/root/out")

	# reports_json is basically unused because we should use repros
	reports_json = json.load(args.reports_file)
	# prevrun_json contains the results of the previous run, which we need to extend
	prevrun_json = json.load(args.record_file)
	# repros has _all_ of the available reproducers
	repros = kdo.parse_reports_json(reports_path, reports_json)
	# prevruns is a dict of all previous runs indexed by id
	prevruns = dict()
	for e in prevrun_json:
		prevruns[e['id']] = e

	# we merge all runs into prevrun_json
	for r in repros:
		if r['fault_type'] != "memcpy": continue
		if r['id'] not in prevruns:
			r['new'] = True
			prevrun_json.append(r)

	# from this point onwards we only use prevrun_json
	del reports_json
	del prevruns

	## # repro_id = "d73eeb2bc242f73eaaba9f0ef8118f82e93bb55b" # no taint
	## repro_id = "ac3bad7a701d9e0e4c6e3cce1f68392a5787dab7" # did not crash
	## # repro_id = "6e675f56f166258c81bc8343ed6b2207f05a00e6" # af_x25
	## # repro_id = "7857221bdd5e7ccc9978bf7dd186ac5157bcdb7b" # msg_msg
	## #repro_id = "c9f21bbd839ed1c76b88278ed7c77de8b7ac7c8f"
	## #repro_id = "428efbae6f77ce4c31be437177416ce2b15d7786" super slow


	#################
	# 3) get rootfs #
	#################
	image_path = f'rootfs.qcow2'
	rootfs_path = "rootfs/"
	busybox_path="busybox/"

	kdo.copy_repros_rootfs(rootfs_path, repros)
	del repros

	image_path = os.path.join(os.getcwd(), image_path)
	rootfs_path = os.path.join(os.getcwd(), rootfs_path)
	busybox_path = os.path.join(os.getcwd(), busybox_path)

	rootfs = Rootfs(
			None,
			image_path=image_path,
			rootfs_path=rootfs_path,
			busybox_path=busybox_path,
			avoid_create=(os.path.isfile(image_path)))
	kernel = Kernel('/root/kernel')

	record_results = []

	for repro in prevrun_json:
		# # don't rerun repros that didn't crash
		# if 'err' in repro and repro['err'] == "no_crash":
		# 	continue
		# don't rerun repros that already ran fast
		if 'err' not in repro: # and 'time' in repro and repro['time'] < 150:
			print(f'skipping: {repro["id"]}', file=sys.stderr)
			continue

		print(f'running: {repro["id"]}', file=sys.stderr)

		os.chdir("/root/out")
		#########################
		# 1) determine repro id #
		#########################
		########################################
		# 2) determine call id from repro data #
		########################################

		repro_id = repro['id']
		callid = int(repro['call_id'])

		#############
		# 4) record #
		#############

		oldrepropath = os.path.join(os.getcwd(), repro['id'])

		newrepropath = os.path.join(os.getcwd(), repro['id']+".new")
		if os.path.isdir(newrepropath):
			shutil.rmtree(newrepropath)
		os.makedirs(newrepropath)

		os.chdir(newrepropath)

		start = time.time()
		timeout = kdo.record(kernel, rootfs, 480, repro_id)
		end = time.time()
		print(f'time: {end - start}')

		if timeout:
			if 'new' in repro:
				del repro['new']
				repro['time'] = end - start
				repro.update({'err': "timeout"})
				if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
				os.rename(newrepropath, oldrepropath)
				print('new:', file=sys.stderr)
			else:
				shutil.rmtree(newrepropath)
				print('timed out, discarding:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		##########################
		# 5) determine addresses #
		##########################

		record_logging = []
		with open('./panda_logging.txt', 'r') as f:
			lines = f.readlines()
			if len(lines) > 0:
				record_logging = lines[-1].split("', '")

		if len(record_logging) == 0:
			if 'new' in repro:
				del repro['new']
				repro['time'] = end - start
				repro.update({'err': "nodata"})
				if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
				os.rename(newrepropath, oldrepropath)
				print('new:', file=sys.stderr)
			else:
				shutil.rmtree(newrepropath)
				print('nodata, discarding:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		if re.search('REPRODUCER DID NOT CRAS', record_logging[len(record_logging)-1]):
			if 'new' in repro:
				del repro['new']
				repro['time'] = end - start
				repro.update({'err': "no_crash"})
				if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
				os.rename(newrepropath, oldrepropath)
				print('new:', file=sys.stderr)
			else:
				shutil.rmtree(newrepropath)
				print('no crash, discarding:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		r = re.compile('^.*Write of size (?P<size>.*) at addr (?P<addr>.*) by task.*$')
		addrs = [m.groupdict() for m in (r.match(line) for line in record_logging) if m]

		if len(addrs) == 0:
			if 'new' in repro:
				del repro['new']
				repro['time'] = end - start
				repro.update({'err': "no_dst"})
				if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
				os.rename(newrepropath, oldrepropath)
				print('new:', file=sys.stderr)
			else:
				shutil.rmtree(newrepropath)
				print('no dst, discarding:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		target_addr = int(addrs[0]['addr'], 16)

		if len(addrs) == 1:
			if 'new' in repro:
				del repro['new']
				repro['time'] = end - start
				repro.update({'err': "no_src"})
				if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
				os.rename(newrepropath, oldrepropath)
				print('new:', file=sys.stderr)
			else:
				shutil.rmtree(newrepropath)
				print('no src, discarding:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		cfu_dst_addr = int(addrs[1]['addr'], 16)

		if 'err' in repro or end-start < repro['time']:
			if 'err' in repro: del repro['err']
			repro['time'] = end - start
			repro.update({'src_addr': cfu_dst_addr, 'dst_addr': target_addr})
			if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
			os.rename(newrepropath, oldrepropath)
			print('updated:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		if 'new' in repro:
			del repro['new']
			repro['time'] = end - start
			repro.update({'src_addr': cfu_dst_addr, 'dst_addr': target_addr})
			if os.path.isdir(oldrepropath): shutil.rmtree(oldrepropath)
			os.rename(newrepropath, oldrepropath)
			print('new:', file=sys.stderr)
			print(repro, file=sys.stderr)
			continue

		print(f'keeping old run ({end-start}):', file=sys.stderr)
		shutil.rmtree(newrepropath)
		print(repro, file=sys.stderr)

	json.dump(prevrun_json, args.outfile, indent=5, sort_keys=True)

	return

if __name__ == '__main__':
	main()

