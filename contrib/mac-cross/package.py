#!/usr/bin/env python3
"""Package static macOS binaries and a relocatable Qt application bundle."""
import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify import CPU_TYPES, encoded_version, verify_binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'depends', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--minimum', default='12.0')
    parser.add_argument('--architecture', choices=CPU_TYPES, default='x86_64')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    config = (args.build / 'src/config/neurai-config.h').read_text()
    match = re.search(r'^#define PACKAGE_VERSION "([^"]+)"', config, re.MULTILINE)
    if not match:
        raise ValueError('Cannot read the configured project version')
    name = f'neurai-{match[1]}-macos-{args.architecture}'
    stage = args.output / name
    if stage.exists():
        shutil.rmtree(stage)
    (stage / 'bin').mkdir(parents=True)
    sources = [args.build / 'src' / binary for binary in ('neuraid', 'neurai-cli', 'neurai-tx')]
    test = args.build / 'src/test/test_neurai'
    if test.exists():
        sources.append(test)
    minimum = encoded_version(args.minimum)
    sdk = encoded_version(os.environ.get('OSX_SDK_VERSION', '14.5'))
    reports = [verify_binary(path, minimum, sdk, args.architecture) for path in sources]
    for path in sources:
        shutil.copy2(path, stage / 'bin' / path.name)
    shutil.copy2(args.source / 'COPYING', stage / 'COPYING')
    license_dir = args.depends / 'share/licenses'
    if license_dir.exists():
        shutil.copytree(license_dir, stage / 'licenses')
    archive = args.output / f'{name}.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        output.add(stage, arcname=name)
    packages = [archive]

    gui = args.build / 'src/qt/neurai-qt'
    if gui.exists() and not os.environ.get('NO_QT'):
        reports.append(verify_binary(gui, minimum, sdk, args.architecture))
        bundle = stage / 'Neurai-Qt.app'
        contents = bundle / 'Contents'
        executable = contents / 'MacOS'
        resources = contents / 'Resources'
        executable.mkdir(parents=True)
        resources.mkdir(parents=True)
        for path, filename in [(gui, 'Neurai-Qt')] + [(path, path.name) for path in sources if path.name != 'test_neurai']:
            shutil.copy2(path, executable / filename)
        info = plistlib.loads((args.build / 'share/qt/Info.plist').read_bytes())
        if encoded_version(info['LSMinimumSystemVersion']) != minimum:
            raise ValueError('Info.plist and the Mach-O deployment target disagree')
        info['CFBundleDisplayName'] = 'Neurai'
        (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
        (contents / 'PkgInfo').write_bytes(b'APPL????')
        shutil.copy2(args.source / 'src/qt/res/icons/neurai.icns', resources / 'neurai.icns')
        shutil.copy2(args.source / 'COPYING', resources / 'COPYING')
        if license_dir.exists():
            shutil.copytree(license_dir, resources / 'licenses')
        (resources / 'qt.conf').write_text('[Paths]\nPrefix=..\nTranslations=Resources/translations\n')
        translations = resources / 'translations'
        translations.mkdir()
        for path in sorted((args.depends / 'translations').glob('*.qm')):
            shutil.copy2(path, translations / path.name)
        zipped = args.output / f'{name}-unsigned.zip'
        with zipfile.ZipFile(zipped, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
            for path in sorted(bundle.rglob('*')):
                if path.is_file():
                    output.write(path, path.relative_to(stage))
        with zipfile.ZipFile(zipped) as output:
            if output.testzip() is not None:
                raise ValueError('Application ZIP integrity check failed')
        packages.append(zipped)
    report = {'version': match[1], 'architecture': args.architecture, 'minimum_macos': args.minimum,
              'signed': False, 'runtime_tested_on_macos': False, 'binaries': reports,
              'packages': [{'path': str(path.resolve()), 'size_bytes': path.stat().st_size,
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in packages]}
    for package in report['packages']:
        path = Path(package['path'])
        path.with_name(path.name + '.sha256').write_text(f"{package['sha256']}  {path.name}\n")
    (args.output / 'macos-build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['packages'], indent=2))


if __name__ == '__main__':
    main()
