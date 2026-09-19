#!/usr/bin/env python3
"""Check canonical v1 contract prefixes and rejection of retired address strings."""
import importlib.util
import json
from pathlib import Path
import tempfile
from generate_authscript_vectors import bech32m

spec = importlib.util.spec_from_file_location('helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    root = Path(tempfile.mkdtemp(prefix='authscript-prefix-'))
    node = h.Node(Path('/root/Neurai/src'), root/'node', ['-pqwallet=1'])
    results = []
    def check(name, value):
        results.append({'case': name, 'passed': bool(value)})
        if not value:
            raise AssertionError(name)
    try:
        node.ready()
        address = node.rpc('getnewaddress')
        check('canonical_v1', address.startswith('tnc1p'))
        details = node.rpc('validateaddress', address)
        check('owned_v1', details['isvalid'] and details['ismine'])
        program = bytes.fromhex(details['scriptPubKey'])[2:]
        check('native_v1_program', len(program) == 32 and details['scriptPubKey'].startswith('5120'))
        for hrp in ('tnq', 'nq', 'nc', 'tpq'):
            wrong = bech32m(hrp, 1, program)
            check('reject_'+hrp, not node.rpc('validateaddress', wrong)['isvalid'])
        for version in (0, 2, 3, 4):
            check('reject_contract_version_'+str(version), not node.rpc('validateaddress', bech32m('tnc', version, program))['isvalid'])
        signature = node.rpc('signmessage', address, 'contract-prefix')
        check('message_roundtrip', node.rpc('verifymessage', address, signature, 'contract-prefix'))
        check('pq_v2_unchanged', node.rpc('getnewaddress', '', 'pq').startswith('tpq1z'))
    finally:
        node.close()
        (root/'report.json').write_text(json.dumps({'results': results, 'binary_sha256': h.digest_file(Path('/root/Neurai/src/neuraid'))}, indent=2)+'\n')
        print('Report:', root/'report.json')
    print('PASS:', len(results))


if __name__ == '__main__':
    main()
