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
// AES UVM Testbench — Environment
// =============================================================================
// Top-level UVM environment containing:
//   - aes_agent       (active)
//   - aes_scoreboard
//   - aes_coverage
//
// Analysis port connections:
//   agent.monitor.ap_in  → scoreboard.ae_in
//   agent.monitor.ap_out → scoreboard.ae_out
//   agent.monitor.ap_out → coverage (via subscriber write())
//
// A separate "context" analysis port on the scoreboard receives the full
// seq_item (with key + iv fields) so the reference model can compute the
// expected result.  The env wires the agent's broadcast port to this.
// =============================================================================

`ifndef AES_ENV_SV
`define AES_ENV_SV

`include "uvm_macros.svh"

class aes_env extends uvm_env;

  import aes_pkg::*;

  `uvm_component_utils(aes_env)

  // Sub-components
  aes_agent       agent;
  aes_scoreboard  scoreboard;
  aes_coverage    coverage;

  // Broadcast analysis port for full context items (key+iv included).
  // Sequences write to this port after each item is sent; the env fans it
  // out to the scoreboard context FIFO.
  uvm_analysis_port #(aes_seq_item) ap_context;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  // ---------------------------------------------------------------------------
  // build_phase
  // ---------------------------------------------------------------------------
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    agent      = aes_agent::type_id::create      ("agent",      this);
    scoreboard = aes_scoreboard::type_id::create  ("scoreboard", this);
    coverage   = aes_coverage::type_id::create    ("coverage",   this);

    ap_context = new("ap_context", this);
  endfunction : build_phase

  // ---------------------------------------------------------------------------
  // connect_phase: wire analysis ports
  // ---------------------------------------------------------------------------
  function void connect_phase(uvm_phase phase);
    // Monitor input captures → scoreboard input FIFO
    agent.monitor.ap_in.connect(scoreboard.ae_in);

    // Monitor output captures → scoreboard output FIFO
    agent.monitor.ap_out.connect(scoreboard.ae_out);

    // Monitor output captures → coverage collector
    agent.monitor.ap_out.connect(coverage.analysis_export);

    // Full-context items (with key/iv) → scoreboard context FIFO
    ap_context.connect(scoreboard.ae_context);
  endfunction : connect_phase

  // ---------------------------------------------------------------------------
  // start_of_simulation_phase
  // ---------------------------------------------------------------------------
  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("ENV", "AES UVM Environment topology:", UVM_MEDIUM)
    this.print();
  endfunction : start_of_simulation_phase

endclass : aes_env

`endif // AES_ENV_SV
