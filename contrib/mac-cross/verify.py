#!/usr/bin/env python3
"""Check cross-built macOS executables without trying to run them on Linux."""
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def encoded_version(value):
    parts = [int(part) for part in value.split('.')]
    if not 1 <= len(parts) <= 3 or any(part < 0 or part > 255 for part in parts):
        raise ValueError(f'Invalid version: {value}')
    parts += [0] * (3 - len(parts))
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def version(value):
    return f'{value >> 16}.{(value >> 8) & 255}.{value & 255}'


def verify_binary(path, minimum, sdk):
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError(f'{path}: truncated executable')
    magic, cpu, _, kind, count, size, flags, _ = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x01000007 or kind != 2:
        raise ValueError(f'{path}: expected an x86-64 Mach-O executable')
    if not flags & 0x200000 or flags & 0x20000:
        raise ValueError(f'{path}: PIE disabled or executable stack enabled')
    end = 32 + size
    if end > len(data):
        raise ValueError(f'{path}: truncated load commands')
    offset = 32
    linked = []
    recorded_min = recorded_sdk = None
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError(f'{path}: invalid load command count')
        cmd, length = struct.unpack_from('<2I', data, offset)
        if length < 8 or offset + length > end:
            raise ValueError(f'{path}: invalid load command length')
        if cmd == 0x32:
            if length < 24:
                raise ValueError(f'{path}: truncated build version')
            platform, recorded_min, recorded_sdk, _ = struct.unpack_from('<4I', data, offset + 8)
            if platform != 1:
                raise ValueError(f'{path}: platform is not macOS')
        elif cmd == 0x24:
            if length < 16:
                raise ValueError(f'{path}: truncated macOS version')
            recorded_min, recorded_sdk = struct.unpack_from('<2I', data, offset + 8)
        elif cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            if length < 24:
                raise ValueError(f'{path}: truncated dylib command')
            start = offset + struct.unpack_from('<I', data, offset + 8)[0]
            if not offset + 24 <= start < offset + length:
                raise ValueError(f'{path}: invalid dylib name')
            stop = data.find(b'\0', start, offset + length)
            if stop == -1:
                raise ValueError(f'{path}: unterminated dylib name')
            linked.append(data[start:stop].decode())
        elif cmd == 0x19:
            if length < 72:
                raise ValueError(f'{path}: truncated segment command')
            protection = struct.unpack_from('<I', data, offset + 60)[0]
            if protection & 2 and protection & 4:
                raise ValueError(f'{path}: writable executable segment')
        offset += length
    if offset != end:
        raise ValueError(f'{path}: load command size mismatch')
    if recorded_min != minimum or recorded_sdk != sdk:
        raise ValueError(f'{path}: SDK/deployment target differs from the configured values')
    if not linked or any(not name.startswith(('/usr/lib/', '/System/Library/')) for name in linked):
        raise ValueError(f'{path}: unexpected dynamic dependencies: {linked}')
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(data).hexdigest(),
            'size_bytes': len(data), 'architecture': 'x86_64', 'minimum_macos': version(recorded_min),
            'sdk': version(recorded_sdk), 'pie': True, 'executable_stack': False,
            'dynamic_dependencies': linked, 'executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minimum', default='12.0')
    parser.add_argument('--sdk', default='14.5')
    parser.add_argument('--depends', type=Path)
    parser.add_argument('--ar', default='llvm-ar')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('binaries', nargs='+', type=Path)
    args = parser.parse_args()
    # Do not leave a previous successful report behind after a failed check.
    args.output.unlink(missing_ok=True)
    binaries = [verify_binary(path, encoded_version(args.minimum), encoded_version(args.sdk)) for path in args.binaries]
    archives = []
    if args.depends:
        for path in sorted((args.depends / 'lib').glob('*.a')):
            members = subprocess.check_output([args.ar, 't', str(path)], text=True).splitlines()
            if not members:
                continue  # Boost.System is header-only and its compatibility archive is empty.
            data = subprocess.check_output([args.ar, 'p', str(path), members[0]])
            if len(data) < 12 or struct.unpack_from('<2I', data) != (0xfeedfacf, 0x01000007):
                raise ValueError(f'{path}: dependency object is not x86-64 Mach-O')
            archives.append({'name': path.name, 'sample_member': members[0], 'format': 'Mach-O', 'architecture': 'x86_64'})
    report = {'success': True, 'runtime_tested_on_macos': False, 'binaries': binaries, 'dependency_archives': archives}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Verified {len(binaries)} macOS executables and {len(archives)} dependency archives: {args.output}')


if __name__ == '__main__':
    main()
