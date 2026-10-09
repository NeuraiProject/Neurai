#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Start the actual Qt application without a wallet and stop it through RPC.

Requires a Qt build with the offscreen platform plugin. Runs on isolated regtest
with fresh data and GUI settings; no third-party Python modules are required.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neurai-qt', required=True, type=Path)
    parser.add_argument('--neurai-cli', required=True, type=Path)
    parser.add_argument('--tmpdir', required=True, type=Path)
    args = parser.parse_args()
    directory = args.tmpdir.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    data = directory / 'data'
    data.mkdir()
    runtime = directory / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen',
               XDG_CONFIG_HOME=str(directory / 'config'),
               XDG_CACHE_HOME=str(directory / 'cache'), XDG_RUNTIME_DIR=str(runtime))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    common = ['-datadir=' + str(data), '-regtest', '-rpcport=' + str(port),
              '-rpcuser=qt-startup-test', '-rpcpassword=isolated-test']
    cli = [str(args.neurai_cli.resolve()), *common]
    command = [str(args.neurai_qt.resolve()), *common, '-disablewallet', '-server',
               '-listen=0', '-connect=0', '-dnsseed=0', '-discover=0', '-splash=0', '-par=2']
    with (directory / 'console.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 120
            while True:
                assert process.poll() is None, ('GUI exited during startup', process.returncode)
                result = subprocess.run([*cli, 'getblockchaininfo'], env=env,
                                        capture_output=True, text=True, timeout=20)
                if result.returncode == 0:
                    info = json.loads(result.stdout)
                    assert info['chain'] == 'regtest' and info['blocks'] == 0
                    break
                assert time.monotonic() < deadline, result.stderr
                time.sleep(0.1)
            # RPC starts before the queued GUI initialization callback. Let that
            # callback run so a crash while creating the window cannot pass.
            alive_until = time.monotonic() + 3
            while time.monotonic() < alive_until:
                assert process.poll() is None, ('GUI exited after RPC startup', process.returncode)
                time.sleep(0.1)
            subprocess.run([*cli, 'stop'], env=env, check=True, capture_output=True, timeout=20)
            assert process.wait(timeout=60) == 0
            print(json.dumps(dict(success=True, wallet_disabled=True, clean_shutdown=True)))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
