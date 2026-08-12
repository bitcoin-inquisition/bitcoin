# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(bench_bitcoin
  bench_bitcoin.cpp
  bench.cpp
  nanobench.cpp
# Benchmarks:
  addrman.cpp
  base58.cpp
  bech32.cpp
  bip324_ecdh.cpp
  block_assemble.cpp
  ccoins_caching.cpp
  chacha20.cpp
  checkblock.cpp
  checkblockindex.cpp
  checkqueue.cpp
  cluster_linearize.cpp
  crypto_hash.cpp
  descriptors.cpp
  disconnected_transactions.cpp
  duplicate_inputs.cpp
  ellswift.cpp
  examples.cpp
  gcs_filter.cpp
  hashpadding.cpp
  index_blockfilter.cpp
  load_external.cpp
  lockedpool.cpp
  logging.cpp
  mempool_ephemeral_spends.cpp
  mempool_eviction.cpp
  mempool_stress.cpp
  merkle_root.cpp
  parse_hex.cpp
  peer_eviction.cpp
  poly1305.cpp
  pool.cpp
  prevector.cpp
  random.cpp
  readwriteblock.cpp
  rollingbloom.cpp
  rpc_blockchain.cpp
  rpc_mempool.cpp
  sign_transaction.cpp
  streams_findbyte.cpp
  strencodings.cpp
  util_time.cpp
  verify_script.cpp
  xor.cpp
)

add_executable(bench_varops
  bench_varops.cpp
  bench.cpp
  nanobench.cpp
)

target_link_libraries(bench_varops
  core_interface
  test_util
  bitcoin_node
  secp256k1
  Boost::headers
)

include(TargetDataSources)
target_raw_data_sources(bench_bitcoin NAMESPACE benchmark::data
  data/block413567.raw
)

target_link_libraries(bench_bitcoin
  core_interface
  test_util
  bitcoin_node
  Boost::headers
)

if(ENABLE_WALLET)
  target_sources(bench_bitcoin
    PRIVATE
      coin_selection.cpp
      wallet_balance.cpp
      wallet_create.cpp
      wallet_create_tx.cpp
      wallet_loading.cpp
      wallet_ismine.cpp
      wallet_migration.cpp
  )
  target_link_libraries(bench_bitcoin bitcoin_wallet)
endif()

add_test(NAME bench_sanity_check_high_priority
  COMMAND bench_bitcoin -sanity-check -priority-level=high
)

add_test(NAME bench_varops_rejects_unknown_opcode
  COMMAND bench_varops --silent
          --opcodes OP_NOP OP_DOES_NOT_EXIST
)
set_tests_properties(bench_varops_rejects_unknown_opcode PROPERTIES WILL_FAIL TRUE)

add_test(NAME bench_varops_reports_output_failure
  COMMAND bench_varops --silent --epochs 1
          --opcodes OP_NOP
          --file ${CMAKE_CURRENT_BINARY_DIR}/bench_varops_missing_directory/results.csv
)
set_tests_properties(bench_varops_reports_output_failure PROPERTIES WILL_FAIL TRUE)

install_binary_component(bench_bitcoin)
