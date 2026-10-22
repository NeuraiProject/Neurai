#!/usr/bin/env python3
"""Run upstream SIMD/Fugue bit-vector tests against this tree's C algorithms.

Pass a separately verified sphlib source checkout (see README.md). This script
copies the test harness and fixes its memcpy(NULL, 0) call only. It never changes
production code, expected digests, or the original upstream source directory.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('upstream', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root, upstream, out = (p.resolve() for p in (args.root, args.upstream, args.output))
    out.mkdir(parents=True, exist_ok=True)
    for name in ['test_fugue.c', 'test_simd.c', 'test_types.c',
                 'test_digest_helper.c', 'utest.c', 'utest.h']:
        (out / name).write_bytes((upstream / 'c' / name).read_bytes())
    helper = out / 'test_digest_helper.c'
    text = helper.read_text()
    old = 'memcpy(dbuf, utest_nist_data(u), dbuf_len);'
    if text.count(old) != 1:
        raise SystemExit('Unexpected upstream harness; check the pinned revision')
    helper.write_text(text.replace(old, 'if (dbuf_len != 0) ' + old))
    env = {**os.environ, 'ASAN_OPTIONS': 'handle_segv=0:detect_leaks=0',
           'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    variants = [('gcc', 'gcc', ['-O2']),
                ('gcc-sanitize', 'gcc', ['-O1', '-fsanitize=address,undefined',
                                       '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']),
                ('clang', 'clang-14', ['-O3'])]
    results = []
    for variant, compiler, flags in variants:
        for algorithm in ['simd', 'fugue', 'types']:
            name = variant + '-' + algorithm
            exe = out / name
            sources = [out / ('test_' + algorithm + '.c'), out / 'utest.c']
            if algorithm != 'types':
                sources.append(root / 'src/algo' / (algorithm + '.c'))
            command = [compiler, '-std=c11', *flags, '-I' + str(root / 'src/algo'),
                       *map(str, sources), '-o', str(exe)]
            with (out / (name + '-build.log')).open('wb') as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            with (out / (name + '.log')).open('wb') as log:
                result = subprocess.run([str(exe)], stdout=log, stderr=subprocess.STDOUT,
                                        env=env, timeout=180)
            results.append({'variant': variant, 'test': algorithm,
                            'exit_code': result.returncode,
                            'published_vectors': 8192 if algorithm != 'types' else None})
            (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            if result.returncode:
                raise SystemExit('Test failed; see ' + str(out / (name + '.log')))
            print(name, 'passed', flush=True)


if __name__ == '__main__':
    main()
