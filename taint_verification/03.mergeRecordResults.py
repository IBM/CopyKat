#!/usr/bin/env python3

from typing import Optional

import argparse
import pathlib
import json
import os
import re

def main() -> None:
	opts = argparse.ArgumentParser(
			description='Parse the repro logs and extract info into computer parsable format')
	opts.add_argument('--infile', type=argparse.FileType('r'), required=True,
		help='Input file')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	opts.add_argument('--recordfile', type=argparse.FileType('r'), required=True,
		help='Record file')
	args = opts.parse_args()

	data = json.load(args.infile)
	recr = json.load(args.recordfile)

	recd = dict()
	for r in recr:
		recd[r['id']] = r

	for d in data:
		if d['id'] in recd:
			rr = recd[d['id']]
			del rr["call_id"]
			del rr["fault_type"]
			del rr["id"]
			d.update({"record" : rr})

	json.dump(data, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
	main()
