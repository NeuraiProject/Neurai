#!/usr/bin/env python3
"""Compile current Qt dialog translation units with Docker Qt6; no GUI/link test."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
out = Path(tempfile.mkdtemp(prefix='qt-dialog-compile-'))
report = {'results': [], 'scope': 'translation units only, no linking or visual test'}
subprocess.run(['protoc', '--proto_path=' + str(root / 'src/qt'), '--cpp_out=' + str(out), str(root / 'src/qt/paymentrequest.proto')], check=True)
flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', 'Qt6Widgets', 'Qt6Network'], text=True))
for name in ('coincontroldialog', 'assetcontroldialog', 'signverifymessagedialog'):
    form = root / 'src/qt/forms' / (name + '.ui')
    source = root / 'src/qt' / (name + '.cpp')
    ui = out / ('ui_' + name + '.h')
    subprocess.run(['/usr/lib/qt6/libexec/uic', str(form), '-o', str(ui)], check=True)
    command = ['g++', '-std=c++20', '-fPIC', '-DHAVE_CONFIG_H', '-I' + str(root / 'src'),
               '-I/root/Neurai/src', '-I' + str(root / 'src/leveldb/include'), '-I' + str(root / 'src/univalue/include'), '-I' + str(out), '-I' + str(root / 'src/qt'),
               '-I/root/Neurai/depends/x86_64-pc-linux-gnu/include', *flags,
               '-c', str(source), '-o', str(out / (name + '.o'))]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (out / (name + '.log')).write_text(result.stdout)
    report['results'].append({'source': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                              'command': command, 'passed': result.returncode == 0})
    print(name, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
    if result.returncode:
        print(result.stdout[-6000:], flush=True)
        break
report['passed'] = sum(r['passed'] for r in report['results'])
report['failed'] = sum(not r['passed'] for r in report['results'])
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('Report:', out / 'report.json')
raise SystemExit(int(report['failed'] != 0))
