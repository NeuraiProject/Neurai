#!/usr/bin/env python3
"""Build the network-free SPH differential runner in a configured source tree."""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--opt', default='-O2', help='use --opt=-O0, etc.')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--portable', action='store_true')
    args = parser.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    flags = [args.opt, '-g1', '-ffunction-sections', '-fdata-sections',
             '-DHAVE_CONFIG_H', '-fstrict-aliasing', '-Werror=strict-aliasing',
             '-I' + str(root / 'src'), '-I' + str(root / 'src/crypto/ethash/include')]
    if args.sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie']
    if args.portable:
        flags += ['-DSPH_UNALIGNED=0', '-DSPH_NO_ASM=1']
    files = ['blake.c', 'bmw.c', 'groestl.c', 'jh.c', 'keccak.c', 'skein.c',
             'luffa.c', 'cubehash.c', 'shavite.c', 'simd.c', 'echo.c', 'hamsi.c',
             'fugue.c', 'shabal.c', 'whirlpool.c', 'sph_sha2big.c', 'tiger.cpp']
    commands = []
    for name in files:
        cxx = name.endswith('.cpp')
        commands.append([args.cxx if cxx else args.cc, *flags,
                         '-std=c++20' if cxx else '-std=c11', '-c',
                         str(root / 'src/algo' / name), '-o', str(out / (name + '.o'))])

    def compile_one(cmd):
        return cmd, subprocess.run(cmd, capture_output=True, text=True)

    with (out / 'build.log').open('w') as log:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(compile_one, commands))
        for cmd, result in results:
            log.write(json.dumps(cmd) + '\n' + result.stdout + result.stderr)
        if any(result.returncode for _, result in results):
            raise SystemExit('Compilation failed; see ' + str(out / 'build.log'))
        link = [args.cxx, *flags, '-std=c++20',
                str(root / 'contrib/devtools/sph/compat.cpp'),
                *[str(out / (name + '.o')) for name in files],
                '-Wl,--gc-sections', '-o', str(out / 'sph-compat')]
        # hash.h includes unused Ethash function-pointer aliases. Section GC
        # removes those references even at -O0, without fake Ethash stubs.
        if args.sanitize:
            link += ['-fsanitize=address,undefined', '-no-pie']
        log.write(json.dumps(link) + '\n')
        log.flush()
        result = subprocess.run(link, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit('Link failed; see ' + str(out / 'build.log'))
    (out / 'build.json').write_text(json.dumps({
        'root': str(root), 'output': str(out), 'compile_commands': commands,
        'link_command': link,
    }, indent=2) + '\n')
    print('Built', out / 'sph-compat')


if __name__ == '__main__':
    main()
