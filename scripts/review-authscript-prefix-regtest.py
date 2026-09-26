#!/usr/bin/env python3
"""Check canonical v1 contract prefixes, rejection of retired address strings,
and that the wallet never manages generic AuthScript v1 addresses."""
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
    node = h.Node(Path('/root/Neurai/src'), root/'node', ['-addresstype=pq'])
    results = []
    def check(name, value):
        results.append({'case': name, 'passed': bool(value)})
        if not value:
            raise AssertionError(name)
    try:
        node.ready()
        # Generic v1 is a contract family: the wallet never hands it out, so the
        # address is built from a fixed 32-byte contract program.
        program = bytes(range(1, 33))
        address = bech32m('tnc', 1, program)
        check('canonical_v1', address.startswith('tnc1p'))
        details = node.rpc('validateaddress', address)
        check('valid_v1', details['isvalid'])
        check('native_v1_program', details['scriptPubKey'] == '5120' + program.hex())
        check('wallet_never_owns_v1', not details['ismine'])
        try:
            node.rpc('getnewaddress', '', 'authscript')
            check('wallet_refuses_authscript_type', False)
        except h.RPCError:
            check('wallet_refuses_authscript_type', True)
        for hrp in ('tnq', 'nq', 'nc', 'tpq'):
            wrong = bech32m(hrp, 1, program)
            check('reject_'+hrp, not node.rpc('validateaddress', wrong)['isvalid'])
        for version in (0, 2, 3, 4):
            check('reject_contract_version_'+str(version), not node.rpc('validateaddress', bech32m('tnc', version, program))['isvalid'])
        try:
            node.rpc('signmessage', address, 'contract-prefix')
            check('wallet_does_not_sign_for_v1', False)
        except h.RPCError:
            check('wallet_does_not_sign_for_v1', True)
        check('pq_v2_unchanged', node.rpc('getnewaddress', '', 'pq').startswith('tpq1z'))
        check('pq_wallet_default_is_v2', node.rpc('getnewaddress').startswith('tpq1z'))
    finally:
        node.close()
        (root/'report.json').write_text(json.dumps({'results': results, 'binary_sha256': h.digest_file(Path('/root/Neurai/src/neuraid'))}, indent=2)+'\n')
        print('Report:', root/'report.json')
    print('PASS:', len(results))


if __name__ == '__main__':
    main()
