#!/usr/bin/env -S python3 -u

import argparse
import json
import os
import re
import shutil
import sys

import rrr
from rrr import Stimulus, Rootfs, Kernel, config
from kdo import analysis3
import time

import multiprocessing as mp

import multiprocessing.pool

class NoDaemonProcess(multiprocessing.Process):
	@property
	def daemon(self):
		return False

	@daemon.setter
	def daemon(self, value):
		pass

class NoDaemonContext(type(multiprocessing.get_context())):
	Process = NoDaemonProcess

# We sub-class multiprocessing.pool.Pool instead of multiprocessing.Pool
# because the latter is only a wrapper function, not a proper class.
class NestablePool(multiprocessing.pool.Pool):
	def __init__(self, *args, **kwargs):
		kwargs['context'] = NoDaemonContext()
		super(NestablePool, self).__init__(*args, **kwargs)

def doit(repro):
	os.chdir("/root/out")

	image_path = f'rootfs.qcow2'
	rootfs_path = "rootfs/"
	busybox_path="busybox/"

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
	# if args.repro_id and args.repro_id != repro['id']: continue

	print("starting on ", repro['id'])

	repro_id = repro['id']
	callid = int(repro['call_id'])
	target_addr = repro['record']['dst_addr']
	cfu_dst_addr = repro['record']['src_addr']
	ctr = repro["replay"]["memcpy_ctr"]

	if not os.path.exists(repro_id):
		os.makedirs(repro_id)

	os.chdir(repro_id)

	analysis3.replay(rootfs, kernel, sink_call_id=callid, target_addr=[target_addr], ref_memcpy_ctr=ctr)

	return True

def main() -> None:
	opts = argparse.ArgumentParser(
			description='Run all the repros with panda syz-rrr')
	opts.add_argument('--record-file', type=argparse.FileType('r'), required=True,
			help='reports json exported by extract-info.py')
	opts.add_argument('--repro-id', nargs='*', required=False, help='repro id to reproduce')
	opts.add_argument('--npar', type=int, default=mp.cpu_count(), required=False, help='parallelism')
	opts.add_argument('--rerun', action='store_true', help='rerun the analysis only for the undone')
	args = opts.parse_args()

	analysis3.update_config()

	os.chdir("/root/out")

	repros = json.load(args.record_file)

	## # repro_id = "d73eeb2bc242f73eaaba9f0ef8118f82e93bb55b" # no taint
	## repro_id = "ac3bad7a701d9e0e4c6e3cce1f68392a5787dab7" # did not crash
	## # repro_id = "6e675f56f166258c81bc8343ed6b2207f05a00e6" # af_x25
	## # repro_id = "7857221bdd5e7ccc9978bf7dd186ac5157bcdb7b" # msg_msg
	## #repro_id = "c9f21bbd839ed1c76b88278ed7c77de8b7ac7c8f"
	## #repro_id = "428efbae6f77ce4c31be437177416ce2b15d7786" super slow

	#################
	# 3) get rootfs #
	#################

	print(f'Starting with parallelism {args.npar}')
	pool = NestablePool(args.npar)

	if args.repro_id:
		tmp = dict()
		for e in args.repro_id:
			tmp[e] = True
		torun = [r for r in repros if r['id'] in tmp]

		res = pool.map(doit, torun)

		print(res)

		return
	elif args.rerun:
		rr = []
		for r in repros:
			if 'err' in r: continue
			af = os.path.join("/root/out/", r["id"], "analysis.json")
			if not os.path.isfile(af):
				rr.append(r)
				print(r['id'])
				continue

		return
		res = pool.map(doit, rr)

		print(res)
	else:
		torun = [r for r in repros if "replay" in r and "err" not in r["replay"]]

		res = pool.map(doit, torun)

		print(res)

		return

if __name__ == '__main__':
	main()

