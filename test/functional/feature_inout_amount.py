from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_uint256, tx_from_hex
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.script import LEAF_VERSION_TAPSCRIPT_64BIT, OP_1, OP_ENDIF, OP_GREATERTHANOREQUAL64, OP_IF, OP_INOUT_AMOUNT, OP_SUB64, CScript, taproot_construct
from test_framework.address import output_key_to_p2tr
from test_framework.util import assert_raises_rpc_error
from test_framework.test_framework import BitcoinTestFramework
class InOutAmountTest(BitcoinTestFramework):

    def add_options(self, parser):
        # idk why but 'createwallet' rpc fails if i don't set this
        # this log occurs in the bitcoind logs saying the wallet is not enabled
        # 2023-09-09T18:17:52.261789Z [init] [wallet/init.cpp:132] [Construct] Wallet disabled!
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1


    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()

    def get_utxo(self, fund_tx, idx):
        spent = None
        # Coin selection
        for utxo in self.nodes[0].listunspent():
            if utxo["txid"] == ser_uint256(fund_tx.vin[idx].prevout.hash)[::-1].hex() and utxo["vout"] == fund_tx.vin[idx].prevout.n:
                spent = utxo

        assert (spent is not None)
        assert (len(fund_tx.vin) == 2)
        return spent

    def create_taproot_utxo(self, amount, scripts = None):
        # modify the transaction to add one output that should spend previous taproot
        # Create a taproot prevout
        addr = self.nodes[0].getnewaddress()

        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]
        tap = taproot_construct(pub, LEAF_VERSION_TAPSCRIPT_64BIT, scripts)
        spk = tap.scriptPubKey
        addr = output_key_to_p2tr(tap.output_pubkey)

        raw_hex = self.nodes[0].createrawtransaction([], [{addr: amount}])

        fund_tx = self.nodes[0].fundrawtransaction(raw_hex, False, )["hex"]

        # Createrawtransaction might rearrage txouts
        prev_vout = None
        for i, out in enumerate(tx_from_hex(fund_tx).vout):
            if spk == out.scriptPubKey:
                prev_vout = i
        signed_raw_tx = self.nodes[0].signrawtransactionwithwallet(fund_tx)
        self.nodes[0].sendrawtransaction(signed_raw_tx['hex'])
        tx = tx_from_hex(signed_raw_tx['hex'])
        tx.rehash()
        self.nodes[0].generate(nblocks=1, invalid_call=False)
        last_blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash())
        assert (tx.hash in last_blk['tx'])

        return tx, prev_vout, spk, sec, pub, tap

    def tapscript_satisfy_test(self, script, fundingAmount, spendingAmount, inputs = None, fail=None,
                               seq = 0, ver = 2, locktime = 0):
        if inputs is None:
            inputs = []
        # Create a taproot utxo
        scripts = [("s0", script)]
        prev_tx, prev_vout, spk, sec, pub, tap = self.create_taproot_utxo(fundingAmount, scripts)

        tx = CTransaction()

        tx.nVersion = ver
        tx.nLockTime = locktime
        # Spend the pegin and taproot tx together
        in_total = prev_tx.vout[prev_vout].nValue #.getAmount()
        fees = 1000
        tap_in_pos = 0

        tx.vin.append(CTxIn(COutPoint(prev_tx.sha256, prev_vout), nSequence=seq))
        tx.vout.append(CTxOut(nValue = spendingAmount, scriptPubKey = spk)) # send back to self
        tx.vout.append(CTxOut(in_total - spendingAmount - fees, spk))


        tx.wit.vtxinwit.append(CTxInWitness())


        suffix_annex = []
        control_block = bytes([tap.leaves["s0"].version + tap.negflag]) + tap.internal_pubkey + tap.leaves["s0"].merklebranch

        wit = inputs + [bytes(tap.leaves["s0"].script), control_block] + suffix_annex
        tx.wit.vtxinwit[tap_in_pos].scriptWitness.stack = wit

        if fail:
            assert_raises_rpc_error(-26, fail, self.nodes[0].sendrawtransaction, tx.serialize().hex())
            return

        self.nodes[0].sendrawtransaction(hexstring = tx.serialize().hex())
        self.nodes[0].generate(1, invalid_call=False)
        last_blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash())
        tx.rehash()
        assert (tx.hash in last_blk['tx'])

    def run_test(self):
        self.log.info("Hello world!")
        self.generate(self.nodes[0], 101)
        self.wait_until(lambda: self.nodes[0].getblockcount() == 101, timeout=5)
        # Test whether the above test framework is working
        self.log.info("Test simple op_1")
        ONE_BTC = 100000000
        self.tapscript_satisfy_test(CScript([OP_1]), fundingAmount=2, spendingAmount=ONE_BTC)

        def le8(x, signed=True):
            return int(x).to_bytes(8, 'little', signed=signed)
        # check we can withdraw up to ONE BTC
        self.tapscript_satisfy_test(CScript([OP_INOUT_AMOUNT, OP_SUB64, OP_IF, le8(ONE_BTC), OP_GREATERTHANOREQUAL64, OP_ENDIF]), fundingAmount=2, spendingAmount=ONE_BTC)
        # check we can't withdraw more than one BTC
        self.tapscript_satisfy_test(CScript([OP_INOUT_AMOUNT, OP_SUB64, OP_IF, le8(ONE_BTC), OP_GREATERTHANOREQUAL64, OP_ENDIF]), fundingAmount=2, spendingAmount=ONE_BTC + 1, fail='Script evaluated without error but finished with a false/empty top stack element')

if __name__ == '__main__':
    InOutAmountTest().main()
