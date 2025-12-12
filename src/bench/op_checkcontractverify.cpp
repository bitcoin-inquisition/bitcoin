// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>

typedef std::vector<unsigned char> valtype;

static void DoubleTweak(benchmark::Bench& bench)
{
    const XOnlyPubKey naked_key{ParseHex(
        "50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0")};

    const std::vector<unsigned char> data(MAX_SCRIPT_ELEMENT_SIZE, 0x42);

    const uint256 merkle_root{ParseHex(
        "E79925EF2A0DF8D2C0C08BFA7474D016384C5FC64C51EFC5E950AA1A97B88B61")};

    const XOnlyPubKey result_key{ParseHex(
        "F2DFC709E477C8D73A3625BC05C370B196703E466EB8655977FF69807EEF8F0E")};

    bench.unit("ccv_doubletweak").run([&] {
        bool ret = result_key.CheckDoubleTweak(naked_key, data, &merkle_root);
        assert(ret);
    });

    const XOnlyPubKey schnorr_key{ParseHex(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")};
    const valtype msg{ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000000")};
    const valtype sig{ParseHex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")};

    bench.unit("verify").run("schnorr-good-verify", [&] {
        auto ret = schnorr_key.VerifySchnorr(uint256(msg), sig);
        assert(ret);
    });
}


BENCHMARK(DoubleTweak, benchmark::PriorityLevel::HIGH);
