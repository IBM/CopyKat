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
	opts.add_argument('--path', type=pathlib.Path, required=True,
		help='path to panda out directory')
	args = opts.parse_args()

	data = json.load(args.infile)

	for d in data:
		an_f = os.path.join(args.path, d['id'], 'analysis.json')
		if not os.path.isfile(an_f):
			continue

		analysis = dict()
		with open(an_f, 'r') as f:
			try:
				analysis = json.load(f)
			except json.decoder.JSONDecodeError:
				continue

		existing = dict()
		if "replay" in d:
			existing = d["replay"]

		for key in existing:
			if key in analysis:
				raise ValueError(f"Key conflict: '{key}' already exists in the first dictionary.")
		merged = existing | analysis

		d.update({"replay" : merged})

		# print(json.dumps(analysis, indent=2))

	json.dump(data, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
	main()
