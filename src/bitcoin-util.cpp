// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <streams.h>
#include <univalue.h>
#include <util/check.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <thread>

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    // evalscript options
    argsman.AddArg("-sigversion", "Specify a script sigversion (base, witness_v0, tapscript).", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddArg("-script_flags", "Specify SCRIPT_VERIFY flags.", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddArg("-tx", "The tx (hex encoded)", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddArg("-input", "The index of the input being spent", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddArg("-spent_output", "The spent prevouts (hex encode TxOut, may be specified multiple times).", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);
    argsman.AddArg("-ipk", "The internal public key for a tapscript spend", ArgsManager::ALLOW_ANY, OptionsCategory::COMMAND_OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("evalscript", "Interpret a bitcoin script", {"-sigversion", "-script_flags", "-tx", "-input", "-spent_output", "-ipk"});

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The bitcoin-util tool provides bitcoin related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  bitcoin-util [options] [command]\n"
                "or:     bitcoin-util [options] grind <hex-block-header>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static UniValue stack2uv(const std::vector<std::vector<unsigned char>>& stack)
{
    UniValue result{UniValue::VARR};
    for (const auto& v : stack) {
        result.push_back(HexStr(v));
    }
    return result;
}

static std::string sigver2str(SigVersion sigver)
{
    switch(sigver) {
    case SigVersion::BASE: return "base";
    case SigVersion::WITNESS_V0: return "witness_v0";
    case SigVersion::TAPROOT: return "taproot";
    case SigVersion::TAPSCRIPT: return "tapscript";
    case SigVersion::TAPSCRIPT_V2: return "tapscript_v2";
    }
    return "unknown";
}

static script_verify_flags parse_verify_flags(const std::string& strFlags)
{
    if (strFlags.empty() || strFlags == "MANDATORY") return MANDATORY_SCRIPT_VERIFY_FLAGS;
    if (strFlags == "STANDARD") return STANDARD_SCRIPT_VERIFY_FLAGS;
    if (strFlags == "NONE") return 0;

    script_verify_flags flags = 0;
    std::vector<std::string> words = util::SplitString(strFlags, ',');

    for (const std::string& word : words)
    {
        if (!g_verify_flag_names.count(word)) continue;
        flags |= g_verify_flag_names.at(word);
    }
    return flags;
}

//! Public key to be used as internal key for dummy Taproot spends.
static const std::vector<unsigned char> NUMS_H{ParseHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")};

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return sig.size() != 0; }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, KeyVersion keyversion, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) const override { return sig.size() != 0; }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

static int EvalScript(const ArgsManager& argsman, const std::vector<std::string>& args, std::string& strPrint)
{
    UniValue result{UniValue::VOBJ};

    script_verify_flags flags{0};
    PrecomputedTransactionData txdata;
    ScriptExecutionData execdata;

    std::unique_ptr<const CTransaction> txTo;
    std::unique_ptr<BaseSignatureChecker> checker;

    SigVersion sigversion = SigVersion::WITNESS_V0;

    if (const auto verstr = argsman.GetArg("-sigversion"); verstr.has_value()) {
        if (*verstr == "base") {
            sigversion = SigVersion::BASE;
        } else if (*verstr == "witness_v0") {
            sigversion = SigVersion::WITNESS_V0;
        } else if (*verstr == "tapscript") {
            sigversion = SigVersion::TAPSCRIPT;
        } else {
            strPrint = strprintf("Unknown -sigversion=%s", *verstr);
            return EXIT_FAILURE;
        }
    }

    const auto verifystr = argsman.GetArg("-script_flags");
    flags = parse_verify_flags(verifystr.value_or(""));

    CScript script{};
    std::vector<std::vector<unsigned char> > stack{};
    if (args.size() > 0) {
        if (IsHex(args[0])) {
            auto h = ParseHex(args[0]);
            script = CScript(h.begin(), h.end());
        } else {
            script = ParseScript(args[0]);
        }

        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i].size() == 0) {
                stack.emplace_back();
            } else if (IsHex(args[i])) {
                stack.push_back(ParseHex(args[i]));
            } else {
                strPrint = strprintf("Initial stack element not valid hex: %s", args[i]);
                return EXIT_FAILURE;
            }
        }
    }

    if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_internal_key.emplace(NUMS_H);
    }

    if (const auto txhex = argsman.GetArg("-tx"); txhex.has_value()) {
        const int input = argsman.GetIntArg("-input", 0);
        const auto spent_outputs_hex = argsman.GetArgs("-spent_output");

        CMutableTransaction mut_tx;
        if (!DecodeHexTx(mut_tx, *txhex)) {
            strPrint = "Could not decode transaction from -tx argument";
            return EXIT_FAILURE;
        }
        txTo = std::make_unique<CTransaction>(mut_tx);

        if (spent_outputs_hex.size() != txTo->vin.size()) {
            strPrint = "When -tx is specified, must specify exactly one -spent_output for each input";
            return EXIT_FAILURE;
        }

        std::vector<CTxOut> spent_outputs;
        for (const auto& outhex : spent_outputs_hex) {
            bool ok = false;
            if (IsHex(outhex)) {
                CTxOut txout;
                std::vector<unsigned char> out(ParseHex(outhex));
                DataStream ss(out);
                try {
                    ss >> txout;
                    if (ss.empty()) {
                        spent_outputs.push_back(txout);
                        ok = true;
                    }
                } catch (const std::exception&) {
                    // fall through
                }
            }
            if (!ok) {
                strPrint = strprintf("Could not parse -spent_output=%s", outhex);
                return EXIT_FAILURE;
            }
        }

        const bool input_in_range = input >= 0 && static_cast<size_t>(input) < spent_outputs.size();
        CAmount amount = (input_in_range ? spent_outputs.at(input).nValue : 0);
        txdata.Init(*txTo, std::move(spent_outputs), /*force=*/true);
        checker = std::make_unique<TransactionSignatureChecker>(txTo.get(), input, amount, txdata, MissingDataBehavior::ASSERT_FAIL);

        if (sigversion == SigVersion::TAPSCRIPT && input >= 0 && input_in_range) {
            if (const auto ipkhex = argsman.GetArg("-ipk"); ipkhex.has_value()) {
                if (!IsHex(*ipkhex) || ipkhex->size() != 64) {
                    strPrint = strprintf("Not a valid x-only pubkey: -ipk=%s", *ipkhex);
                    return EXIT_FAILURE;
                }
                auto ipkbytes = ParseHex(*ipkhex);
                std::copy(ipkbytes.begin(), ipkbytes.end(), execdata.m_internal_key->begin());
            }

            const CTxIn& txin = txTo->vin.at(input);
            execdata.m_annex_present = false;
            if (txin.scriptWitness.stack.size() <= 1) {
                // either key path spend or no witness, so nothing to do here
            } else {
                const auto& top = txin.scriptWitness.stack.back();
                if (top.size() >= 1 && top.at(0) == 0x50) {
                    execdata.m_annex_hash = (HashWriter{} << top).GetSHA256();
                    execdata.m_annex_present = true;
                }
            }
            execdata.m_annex_init = true;
            execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT & TAPROOT_LEAF_MASK, script);
            execdata.m_tapleaf_hash_init = true;
            execdata.m_validation_weight_left = ::GetSerializeSize(stack) + ::GetSerializeSize(script) + VALIDATION_WEIGHT_OFFSET;
            execdata.m_validation_weight_left_init = true;
        }
    } else {
        checker = std::make_unique<DummySignatureChecker>();
    }

    if (sigversion == SigVersion::TAPSCRIPT && !execdata.m_annex_init) {
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        execdata.m_tapleaf_hash = uint256::ZERO;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_validation_weight_left = ::GetSerializeSize(stack) + ::GetSerializeSize(script) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;
    }

    ScriptError serror{};

    UniValue uv_flags{UniValue::VARR};
    for (const auto& el : GetScriptFlagNames(flags)) {
        uv_flags.push_back(el);
    }
    UniValue uv_script{UniValue::VOBJ};
    ScriptToUniv(script, uv_script);
    result.pushKV("script", uv_script);
    result.pushKV("sigversion", sigver2str(sigversion));
    result.pushKV("script_flags", uv_flags);

    std::optional<bool> opsuccess_check;
    if (sigversion == SigVersion::TAPSCRIPT) {
        opsuccess_check = CheckTapscriptOpSuccess(script, flags, SigVersion::TAPSCRIPT, &serror);
    }

    bool success = (opsuccess_check.has_value() ? *opsuccess_check : EvalScript(stack, script, flags, *Assert(checker), sigversion, execdata, &serror));
    if (opsuccess_check.has_value()) {
         result.pushKV("opsuccess_found", true);
    } else if (success) {
        if (stack.empty() || !CastToBool(stack.back())) {
            success = false;
            serror = SCRIPT_ERR_EVAL_FALSE;
        } else if (stack.size() > 1) {
            if (sigversion == SigVersion::WITNESS_V0 || sigversion == SigVersion::TAPSCRIPT) {
                success = false;
                serror = SCRIPT_ERR_CLEANSTACK;
            } else if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
                success = false;
                serror = SCRIPT_ERR_CLEANSTACK;
            }
        }
    }

    result.pushKV("stack-after", stack2uv(stack));

    result.pushKV("sigop-count", (sigversion == SigVersion::TAPSCRIPT ? 0 : script.GetSigOpCount(true)));

    result.pushKV("success", success);
    if (!success) {
        result.pushKV("error", ScriptErrorString(serror));
    }

    strPrint = result.write(2);

    return EXIT_SUCCESS;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "evalscript") {
            ret = EvalScript(args, cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
