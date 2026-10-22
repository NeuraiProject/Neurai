#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Protocol 3 signatures through real RPC: no re-signing of altered requests."""
import base64
import copy
import http.client
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse, unquote

from feature_depin_messaging_permissions import DepinMessagingPermissionsTest, TOKEN
from test_framework.depin import DepinClient, preimage, request_bytes, digest
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


class DepinRequestSignaturesTest(DepinMessagingPermissionsTest):
    def raw_duplicate(self, node, method, request, field):
        parsed = urlparse(node.url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': [request]})
        needle = '"{}": {}'.format(field, json.dumps(request[field]))
        assert needle in body
        body = body.replace(needle, needle + ', ' + needle, 1)
        auth = base64.b64encode((unquote(parsed.username) + ':' + unquote(parsed.password)).encode()).decode()
        try:
            connection.request('POST', '/', body, {'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'})
            response = json.loads(connection.getresponse().read())
            assert_equal(response['error']['code'], -8)
            assert 'duplicate' in response['error']['message']
        finally:
            connection.close()

    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        owner, reader = node.getnewaddress(), node.getnewaddress()
        self.reveal(owner)
        self.reveal(reader)
        node.issue(TOKEN, 100, owner)
        node.generate(1)
        node.transferfromaddress(TOKEN, owner, 10, reader, '', 0, '', owner)
        node.generate(1)
        for name in ['first', 'second']:
            node.depinsendmsg(TOKEN, name, owner)
        client = DepinClient(node)
        bootstrap, info = client.bootstrap()
        assert_equal(info['accepted_protocols'], [3])
        assert_equal(info['protocol'], 3)

        # Exercise the actual CLI as well as HTTP: both positional and named
        # requests must preserve the JSON object and its integer values.
        cli_bootstrap = {'protocol': 3, 'request_id': os.urandom(32).hex(), 'timestamp_ms': 0}
        for response in [node.cli.depingetmsginfo(json.dumps(cli_bootstrap)),
                         node.cli.depingetmsginfo(request=json.dumps(cli_bootstrap))]:
            assert_equal(client.verify('depingetmsginfo', cli_bootstrap, response,
                                       bootstrap['pool_pubkey'])['protocol'], 3)

        self.log.info('Every clear parameter and service binding is signed, without consuming valid nonces')
        nonce = self.challenge(owner, 'admin')
        original = client.prepare('depinclearmsg', TOKEN, owner, nonce)
        cli_signed = node.cli.depinsignrpc('depinclearmsg', json.dumps(original))
        assert_equal(cli_signed['request'], original)
        assert_equal(cli_signed['preimage'], preimage('depinclearmsg', original))
        # Public test material only: no wallet keys/cookies/datadir are exported.
        vector = {'bootstrap_request': cli_bootstrap, 'bootstrap_response': response,
                  'method': 'depinclearmsg', 'request': original,
                  'request_bytes': request_bytes('depinclearmsg', original).hex(),
                  'request_hash': digest(request_bytes('depinclearmsg', original)).hex(),
                  'preimage': cli_signed['preimage'],
                  'signer_pubkey': node.validateaddress(owner)['pubkey']}
        (Path(self.options.tmpdir) / 'depin-v3-interoperability.json').write_text(json.dumps(vector, indent=2) + '\n')

        def refuse(method, request, code=-32600, message=''):
            # Check a correlatable server error against the known real key,
            # even when this test deliberately changes the requested pool.
            def invoke():
                response = getattr(node, method)(request)
                return client.verify(method, request, response, bootstrap['pool_pubkey'])
            assert_raises_rpc_error(code, message, invoke)
            assert_equal(client.bootstrap()[1]['messages'], 2)

        for args in [{'mode': 'all'}, {'mode': 'hours', 'hours': 0}, {'mode': 'hours', 'hours': 7}]:
            changed = copy.deepcopy(original)
            changed['args'] = args
            refuse('depinclearmsg', changed, message='Signature does not match')
        for field, value in [('network', '01'*32), ('instance_id', '02'*32), ('request_id', '03'*32),
                             ('pool_root', TOKEN + '/OTHER'), ('token', TOKEN + '/OTHER'), ('address', reader),
                             ('challenge', '04'*32), ('timestamp_ms', original['timestamp_ms'] + 1)]:
            changed = copy.deepcopy(original)
            changed[field] = value
            refuse('depinclearmsg', changed, code=None)
        changed = copy.deepcopy(original)
        changed['pool_pubkey'] = node.validateaddress(reader)['pubkey']
        refuse('depinclearmsg', changed)
        changed = copy.deepcopy(original)
        changed['protocol'] = 2
        refuse('depinclearmsg', changed, -8, 'protocol 3')
        changed = copy.deepcopy(original)
        changed['args'] = {'mode': 'hours', 'hours': '0'}
        refuse('depinclearmsg', changed, -8, 'integer')
        self.raw_duplicate(node, 'depinclearmsg', original, 'protocol')
        changed = copy.deepcopy(original)
        changed['signature'] = node.signmessage(owner, 'DEPIN-CLEAR|{}|{}|{}'.format(TOKEN, owner, nonce))
        refuse('depinclearmsg', changed, message='Signature does not match')
        assert_raises_rpc_error(-8, 'protocol 3', node.depinclearmsg,
                                TOKEN, owner, nonce, changed['signature'], 'all')
        assert_equal(client.call_request('depinclearmsg', original)['removed'], 0)
        refuse('depinclearmsg', original)

        self.log.info('A valid read proof cannot move to another method, and replay is atomic')
        read_nonce = self.challenge(reader)
        read = client.prepare('depinreceivemsg', TOKEN, reader, read_nonce)
        refuse('depinlistsections', read, message='Signature does not match')
        assert_equal(len(client.call_request('depinreceivemsg', read)['messages']), 2)
        refuse('depinreceivemsg', read)
        timed = self.request(reader)[0]

        def replay_worker(index):
            rpc = get_rpc_proxy(node.url, 940 + index)
            try:
                DepinClient(rpc).call_request('depinchallenge', timed)
                return True
            except JSONRPCException as error:
                assert_equal(error.error['code'], -32600)
                assert 'already used' in error.error['message']
                return False
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(replay_worker, range(2)))
        assert_equal(sum(outcomes), 1)

        self.log.info('Public responses authenticate the actual query and unique request ID')
        query = client.prepare('depingetancestorrecipients', TOKEN)
        altered = copy.deepcopy(query)
        altered['args']['max_results'] = 1
        answer = node.depingetancestorrecipients(altered)
        client.verify('depingetancestorrecipients', altered, answer, bootstrap['pool_pubkey'])
        try:
            client.verify('depingetancestorrecipients', query, answer, bootstrap['pool_pubkey'])
            raise AssertionError('Response accepted for different requested parameters')
        except AssertionError as error:
            assert str(error) != 'Response accepted for different requested parameters'
        for field, value in [('pool_root', 'altered'), ('instance_id', '05'*32), ('body', '7b7d'), ('request_hash', '06'*32)]:
            damaged = copy.deepcopy(answer)
            damaged[field] = value
            try:
                client.verify('depingetancestorrecipients', altered, damaged, bootstrap['pool_pubkey'])
                raise AssertionError('Altered response accepted')
            except AssertionError as error:
                assert str(error) != 'Altered response accepted'

        self.log.info('Clock rollback and restart invalidate operation proofs without losing retained messages')
        old = client.prepare('depinreceivemsg', TOKEN, reader, self.challenge(reader))
        old_instance = old['instance_id']
        node.setmocktime(int(time.time()) - 2)
        assert client.bootstrap()[1]['instance_id'] != old_instance
        refuse('depinreceivemsg', old)
        node.setmocktime(0)
        pending = client.prepare('depinreceivemsg', TOKEN, reader, self.challenge(reader))
        old_instance = pending['instance_id']
        self.restart_node(0, self.depin_args)
        node = self.nodes[0]
        client = DepinClient(node)
        assert client.bootstrap()[1]['instance_id'] != old_instance
        refuse('depinreceivemsg', pending)
        assert_equal(len(self.receive(reader)), 2)
        assert_equal(DepinClient(node).call('depinclearmsg', TOKEN, owner,
                                          self.challenge(owner, 'admin'), {'mode': 'all'})['removed'], 2)


if __name__ == '__main__':
    DepinRequestSignaturesTest().main()
