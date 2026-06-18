#!/usr/bin/env python3

from typing import Optional

import argparse
import pathlib
import json
import os
import re

ACCEPT_REPRO_PATTER = "^accept\(.*\) \(enabled_site: (?P<call_id>[0-9]+), site_type: [0-9]+\)$"

def process_crash(crash_dir) -> Optional[dict]:
	repro_file = os.path.join(crash_dir, "repro.prog")
	if not os.path.isfile(repro_file):
		return None

	with open(repro_file, 'r') as f:
		lines = f.readlines()
		repro_log_lines = [line.rstrip() for line in lines]

	r = re.compile(ACCEPT_REPRO_PATTER)
	kdo_bugs = [m.groupdict() for m in (r.match(line) for line in repro_log_lines) if m]

	if len(kdo_bugs) != 1:
		return None
	kdo_bug = kdo_bugs[0]

	crash_id = os.path.split(crash_dir)[1].removesuffix(".old")
	kdo_bug['id'] = crash_id

	for root, subdirs, files in os.walk(crash_dir):
		for logfile in files:
			if re.match('^repro.log$', logfile):
				pass
			elif re.match('^log[0-9]+$', logfile):
				pass
			else:
				continue

			with open(os.path.join(root, logfile), 'r', encoding = "ISO-8859-1") as f:
				lines = f.readlines()
				log_lines = [line.rstrip() for line in lines]

			r = re.compile(f'^.*KDO: .* hit \(id: (?P<func_offset>.*), callid: {kdo_bug["call_id"]}S\)$')
			log_info = [m.groupdict() for m in (r.match(line) for line in log_lines) if m]
			if len(log_info) == 0: continue

			if len(log_info) > 1:
				raise(BaseException(kdo_bug))

			kdo_bug['site'] = log_info[0]['func_offset']
			return kdo_bug

	raise(BaseException(kdo_bug))

def main() -> None:
	opts = argparse.ArgumentParser(
			description='Parse the repro logs and extract info into computer parsable format')
	opts.add_argument('--crashes', type=pathlib.Path, required=True,
		help='Path to crashes directory to parse')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	args = opts.parse_args()

	bugs = []

	directory = os.fsencode(args.crashes)
	for file in os.listdir(directory):
		dirpath = f'{os.fsdecode(directory)}/{os.fsdecode(file)}'
		if os.path.isdir(dirpath):
			kdo_bug = process_crash(dirpath)
			if kdo_bug:
				bugs.append(kdo_bug)


	json.dump(bugs, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
	main()
