#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
The MCP worker acts on a command once, and never on a copy of its envelope.

The owner sends a command to the bot. A member publishes the same envelope
again under its own name, with a valid signature of its own, and the pool
admits it. The worker runs against a local HTTP endpoint that stands in for
the model: the command reaches it exactly once, and the copy is refused in
every poll without reaching it. After the restart that starts the worker, the
command still opens with the sender key the pool restored from disk.
"""

import copy
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from feature_depin_pool_state import DepinPoolStateTest, TOKEN, private_key
from test_framework.util import assert_equal, wait_until

COMMAND = 'run the envelope check'


class ModelEndpoint(BaseHTTPRequestHandler):
    """Answers like a chat-completions endpoint and records the last user message of each request."""
    received = []

    def reply(self, value):
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply({'data': [{'id': 'local-model'}]})

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        ModelEndpoint.received.append(request['messages'][-1]['content'])
        self.reply({'model': 'local-model', 'choices': [{'message': {'content': 'ack'}}]})

    def log_message(self, *args):
        pass


class DepinMcpEnvelopeTest(DepinPoolStateTest):
    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        owner, bot, member = [node.getnewaddress() for _ in range(3)]
        for address in (owner, bot, member):
            self.reveal(address)
        node.issue(TOKEN, 100, owner)
        node.generate(1)
        for address in (bot, member):
            node.transferfromaddress(TOKEN, owner, 10, address, '', 0, '', owner)
            node.generate(1)

        self.log.info("A command for the bot, and the same envelope published again by a member")
        sent = node.depinsendmsg(TOKEN, '/ai ' + COMMAND, owner)['hash']
        original = next(m for m in self.sequence_page(bot)['messages'] if m['hash'] == sent)
        copied = copy.deepcopy(original)
        copied['sender'] = member
        copied['timestamp'] += 1
        republished = self.submit(self.wrap(copied, private_key(node.dumpprivkey(member))))['hash']

        server = ThreadingHTTPServer(('127.0.0.1', 0), ModelEndpoint)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.log.info("The worker acts on the command once, and refuses the copy in every poll")
            self.restart_node(0, self.depin_args + [
                '-depinmcp=1', '-depinmcpaddress=' + bot,
                '-depinmcpurl=http://127.0.0.1:%d' % server.server_address[1],
                '-depinmcpinterval=1', '-depinmcpcontext=0', '-depinmcpconcurrency=1',
            ])
            log = os.path.join(node.datadir, 'regtest', 'debug.log')
            refused = 'MCPWorker: ignored message %s from %s: addressed to the bot and not authentic' % (republished, member)

            def refusals():
                with open(log, encoding='utf-8', errors='replace') as lines:
                    return lines.read().count(refused)
            wait_until(lambda: ModelEndpoint.received.count(COMMAND) == 1, timeout=60,
                       err_msg='the worker did not act on the command')
            wait_until(lambda: refusals() >= 2, timeout=30, err_msg='the worker did not refuse the copy in two polls')
            assert_equal(ModelEndpoint.received.count(COMMAND), 1)
            assert_equal(set(ModelEndpoint.received) - {'test'}, {COMMAND})

            self.log.info("After the restart the command opens with the sender key restored from disk")
            stored = next(m for m in self.sequence_page(bot)['messages'] if m['hash'] == sent)
            assert_equal(stored['sender_pubkey_hex'], original['sender_pubkey_hex'])
            assert_equal(node.depinopenmsg(bot, stored), '/ai ' + COMMAND)
        finally:
            # The worker may still be talking to the endpoint: stop it first
            self.stop_node(0)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    DepinMcpEnvelopeTest().main()
