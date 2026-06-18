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
	opts.add_argument('--path', type=pathlib.Path, required=True,
		help='Path to the reports')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	args = opts.parse_args()

	reports_path = args.path
	kdo.update_config()

	os.chdir("/root/out")

	reports_json = json.load(args.reports_file)

	repros = kdo.parse_reports_json(reports_path, reports_json)

	#################
	# 3) get rootfs #
	#################
	image_path = f'rootfs.qcow2'
	rootfs_path = "rootfs/"
	busybox_path="busybox/"

	kdo.copy_repros_rootfs(rootfs_path, repros)

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

	for repro in repros:
		if repro['fault_type'] != "memcpy":
			continue

		if len(record_results) > 0:
			print(json.dumps(record_results[len(record_results)-1], indent=2), file=sys.stderr)

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

		if not os.path.exists(repro_id):
			os.makedirs(repro_id)

		os.chdir(repro_id)

		start = time.time()
		timeout = kdo.record(kernel, rootfs, 480, repro_id)
		end = time.time()
		print(f'time: {end - start}')
		repro['time'] = end - start

		if timeout:
			repro['err'] = 'timeout'
			record_results.append(repro)
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
			repro['err'] = 'nodata'
			record_results.append(repro)
			continue

		if re.search('REPRODUCER DID NOT CRAS', record_logging[len(record_logging)-1]):
			repro['err'] = 'no_crash'
			record_results.append(repro)
			continue

		r = re.compile('^.*Write of size (?P<size>.*) at addr (?P<addr>.*) by task.*$')
		addrs = [m.groupdict() for m in (r.match(line) for line in record_logging) if m]

		if len(addrs) == 0:
			repro['err'] = 'no_dst'
			record_results.append(repro)
			continue

		target_addr = int(addrs[0]['addr'], 16)

		if len(addrs) == 1:
			repro['err'] = 'no_src'
			record_results.append(repro)
			continue

		cfu_dst_addr = int(addrs[1]['addr'], 16)

		repro['src_addr'] = cfu_dst_addr
		repro['dst_addr'] = target_addr

		record_results.append(repro)

	json.dump(record_results, args.outfile, indent=5, sort_keys=True)

if __name__ == '__main__':
	main()

