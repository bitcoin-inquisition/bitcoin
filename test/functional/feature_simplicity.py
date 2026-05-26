#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Simplicity deployment activation and basic spend."""

from decimal import Decimal
from io import BytesIO

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CTxInWitness, CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class SimplicityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-vbparams=simplicity:0:{2**63 - 1}"]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Checking initial Simplicity deployment state")
        assert_equal(node.getdeploymentinfo()["deployments"]["simplicity"]["heretical"]["status"], "defined")

        self.log.info("Mining into the signalling period")
        self.generate(self.wallet, 144)
        assert_equal(node.getdeploymentinfo()["deployments"]["simplicity"]["heretical"]["status"], "started")

        self.log.info("Signalling for Simplicity activation")
        signal_version = int(node.getdeploymentinfo()["deployments"]["simplicity"]["heretical"]["signal_activate"], 16)
        coinbase_tx = create_coinbase(node.getblockcount() + 1)
        now = node.getblock(node.getbestblockhash())["time"]
        block = create_block(hashprev=int(node.getbestblockhash(), 16), ntime=now, coinbase=coinbase_tx, version=signal_version)
        block.solve()
        node.submitblock(block.serialize().hex())
        self.generate(node, 144 * 2)
        assert_equal(node.getdeploymentinfo()["deployments"]["simplicity"]["heretical"]["status"], "active")
        self.log.info("Simplicity is active")

        self.log.info("Fund the anyone-can-spend Simplicity address")
        addr = "bcrt1pzjehfs3vskwj6022c255hyh948ecjsqzv25fkm29w7gwzazyccfqt8ksnv"
        utxo = self.wallet.get_utxo()
        fee = Decimal("0.00001000")
        amount = utxo["value"] - fee
        raw = node.createrawtransaction([{"txid": utxo["txid"], "vout": utxo["vout"]}], [{addr: amount}])
        ctx = CTransaction()
        ctx.deserialize(BytesIO(bytes.fromhex(raw)))
        self.wallet.sign_tx(ctx)
        txid = node.sendrawtransaction(ctx.serialize().hex())
        self.generate(self.nodes[0], 1)

        self.log.info("Spend the Simplicity UTXO")
        addr = self.wallet.get_address()
        fee = Decimal("0.00003000")
        in_witness = CTxInWitness()
        simplicity_witness = ""
        simplicity_program = "24"
        cmr = "c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7"
        control_block = "be50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

        raw = self.nodes[0].createrawtransaction([{"txid": txid, "vout": 0}], [{addr: amount - fee}])
        ctx = CTransaction()
        ctx.deserialize(BytesIO(bytes.fromhex(raw)))

        in_witness.scriptWitness.stack = [
            bytes.fromhex(simplicity_witness),
            bytes.fromhex(simplicity_program),
            bytes.fromhex(cmr),
            bytes.fromhex(control_block),
        ]
        ctx.wit.vtxinwit.append(in_witness)
        raw = ctx.serialize().hex()
        txid = self.nodes[0].sendrawtransaction(raw)
        [blockhash] = self.generate(self.nodes[0], 1)
        info = self.nodes[0].getrawtransaction(txid, 1, blockhash)
        assert info["in_active_chain"]
        assert_equal(info["confirmations"], 1)


if __name__ == "__main__":
    SimplicityTest(__file__).main()
