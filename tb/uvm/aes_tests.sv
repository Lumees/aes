// =============================================================================
// Copyright (c) 2026 Lumees Lab / Hasan Kurşun
// SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
//
// Licensed under the Apache License 2.0 with Commons Clause restriction.
// You may use this file freely for non-commercial purposes (academic,
// research, hobby, education, personal projects).
//
// COMMERCIAL USE requires a separate license from Lumees Lab.
// Contact: info@lumeeslab.com · https://lumeeslab.com
// =============================================================================
// AES UVM Testbench — Tests
// =============================================================================
// Test hierarchy:
//
//   aes_base_test      — builds env, prints topology
//     aes_nist_test    — NIST ECB-128/192/256 + CBC-128 + CTR-128 vectors
//     aes_random_test  — 50 random mixed-mode transactions
//     aes_stress_test  — 200 random mixed-mode transactions, max constraints
// =============================================================================

`ifndef AES_TESTS_SV
`define AES_TESTS_SV

`include "uvm_macros.svh"

// ============================================================================
// Base test
// ============================================================================
class aes_base_test extends uvm_test;

  import aes_pkg::*;

  `uvm_component_utils(aes_base_test)

  aes_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  // ---------------------------------------------------------------------------
  // build_phase: create environment; propagate vif
  // ---------------------------------------------------------------------------
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = aes_env::type_id::create("env", this);
  endfunction : build_phase

  // ---------------------------------------------------------------------------
  // start_of_simulation_phase: print UVM topology
  // ---------------------------------------------------------------------------
  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("TEST", "=== AES UVM Testbench ===", UVM_NONE)
    `uvm_info("TEST", "UVM component topology:", UVM_MEDIUM)
    uvm_top.print_topology();
  endfunction : start_of_simulation_phase

  // ---------------------------------------------------------------------------
  // Helper: wire a sequence's context port to the env's ap_context
  // ---------------------------------------------------------------------------
  function void connect_seq_context(aes_base_seq seq);
    seq.ap_context = env.ap_context;
  endfunction : connect_seq_context

  // Default body (must be overridden)
  virtual task run_phase(uvm_phase phase);
    `uvm_warning("TEST", "aes_base_test::run_phase — no sequences run")
  endtask : run_phase

  // ---------------------------------------------------------------------------
  // final_phase: explicitly end objection if still raised
  // ---------------------------------------------------------------------------
  function void report_phase(uvm_phase phase);
    uvm_report_server svr;
    svr = uvm_report_server::get_server();
    if (svr.get_severity_count(UVM_FATAL) + svr.get_severity_count(UVM_ERROR) > 0)
      `uvm_info("TEST", "*** TEST FAILED ***", UVM_NONE)
    else
      `uvm_info("TEST", "*** TEST PASSED ***", UVM_NONE)
  endfunction : report_phase

endclass : aes_base_test


// ============================================================================
// NIST test
// ============================================================================
class aes_nist_test extends aes_base_test;

  `uvm_component_utils(aes_nist_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    aes_nist_ecb_seq ecb_seq;
    aes_nist_cbc_seq cbc_seq;
    aes_nist_ctr_seq ctr_seq;

    phase.raise_objection(this, "aes_nist_test started");

    ecb_seq = aes_nist_ecb_seq::type_id::create("ecb_seq");
    cbc_seq = aes_nist_cbc_seq::type_id::create("cbc_seq");
    ctr_seq = aes_nist_ctr_seq::type_id::create("ctr_seq");

    connect_seq_context(ecb_seq);
    connect_seq_context(cbc_seq);
    connect_seq_context(ctr_seq);

    `uvm_info("NIST_TEST", "Running NIST ECB sequences", UVM_MEDIUM)
    ecb_seq.start(env.agent.sequencer);

    `uvm_info("NIST_TEST", "Running NIST CBC sequence", UVM_MEDIUM)
    cbc_seq.start(env.agent.sequencer);

    `uvm_info("NIST_TEST", "Running NIST CTR sequence", UVM_MEDIUM)
    ctr_seq.start(env.agent.sequencer);

    // Allow pipeline to drain (PIPE_LAT + margin)
    #500ns;

    phase.drop_objection(this, "aes_nist_test complete");
  endtask : run_phase

endclass : aes_nist_test


// ============================================================================
// Random test (50 transactions)
// ============================================================================
class aes_random_test extends aes_base_test;

  `uvm_component_utils(aes_random_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    aes_random_all_modes_seq rand_seq;

    phase.raise_objection(this, "aes_random_test started");

    rand_seq = aes_random_all_modes_seq::type_id::create("rand_seq");
    connect_seq_context(rand_seq);
    rand_seq.num_transactions = 50;

    `uvm_info("RAND_TEST", "Running 50 random mixed-mode transactions", UVM_MEDIUM)
    rand_seq.start(env.agent.sequencer);

    #500ns;
    phase.drop_objection(this, "aes_random_test complete");
  endtask : run_phase

endclass : aes_random_test


// ============================================================================
// Stress test (200 transactions, maximally constrained)
// ============================================================================
class aes_stress_test extends aes_base_test;

  `uvm_component_utils(aes_stress_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  // build_phase: loosen any debug verbosity limits
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    // Suppress UVM_HIGH and UVM_DEBUG info during stress to reduce log volume
    uvm_top.set_report_verbosity_level_hier(UVM_MEDIUM);
  endfunction : build_phase

  virtual task run_phase(uvm_phase phase);
    aes_random_all_modes_seq rand_seq;

    phase.raise_objection(this, "aes_stress_test started");

    rand_seq = aes_random_all_modes_seq::type_id::create("rand_seq");
    connect_seq_context(rand_seq);
    rand_seq.num_transactions = 200;

    `uvm_info("STRESS_TEST", "Running 200 random mixed-mode transactions", UVM_MEDIUM)
    rand_seq.start(env.agent.sequencer);

    // Longer drain time for 200 transactions × pipeline depth
    #2000ns;
    phase.drop_objection(this, "aes_stress_test complete");
  endtask : run_phase

endclass : aes_stress_test

`endif // AES_TESTS_SV
