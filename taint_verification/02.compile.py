#!/usr/bin/env python3

import argparse
import subprocess
import pathlib
import json
import os

def compile_c_repro(path, do_bug, outdir):
    repro_c = os.path.join(path, do_bug['id'], "repro.cprog")
    if not os.path.isfile(repro_c):
        raise BaseException(do_bug['id'])

    repro_out_path = os.path.join(outdir, do_bug['id'], 'repro')

    result = subprocess.run(
            ['gcc', '-static', '-x', 'c', '-O0', repro_c, '-o', repro_out_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        print("stdout:")
        print(result.stdout.decode(errors="replace"))
        print("stderr:")
        print(result.stderr.decode(errors="replace"))
        raise BaseException(do_bug['id'])

def main() -> None:
    opts = argparse.ArgumentParser(
            description='Update call_ids based on disassembling vmlinux')
    opts.add_argument('--reports-file', type=argparse.FileType('r'), required=True,
        help='reports json exported by extract-info.py')
    opts.add_argument('--path', type=pathlib.Path, required=True,
        help='Root folder containing <id>.c repro files')
    opts.add_argument('--outdir', type=pathlib.Path, required=True,
        help='Root folder containing <id>.c repro files')
    args = opts.parse_args()

    kdo_bugs = json.load(args.reports_file)

    for kdo_bug in kdo_bugs:
        compile_c_repro(args.path, kdo_bug, args.outdir)

if __name__ == '__main__':
    main()
