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
// AES UVM Testbench — Top-level Module
// =============================================================================
// Instantiates:
//   - aes_top DUT (KEY_BITS parameterized via +define+KEY_BITS=N or default 128)
//   - Clock generator (10 ns period)
//   - Reset sequence (active-low, deassert after 5 cycles)
//   - aes_if virtual interface
//   - UVM config_db registration
//   - run_test() kick-off
//
// Simulation plusargs:
//   +UVM_TESTNAME=<test>   (e.g., aes_nist_test, aes_random_test)
//   +KEY_BITS=128|192|256  (override DUT key width; default 128)
// =============================================================================

`timescale 1ns/1ps

`include "uvm_macros.svh"

import uvm_pkg::*;
import aes_pkg::*;

// Include all testbench files in order of dependency
`include "aes_seq_item.sv"
`include "aes_if.sv"
`include "aes_driver.sv"
`include "aes_monitor.sv"
`include "aes_scoreboard.sv"
`include "aes_coverage.sv"
`include "aes_agent.sv"
`include "aes_env.sv"
`include "aes_sequences.sv"
`include "aes_tests.sv"

module aes_tb_top;

  // ---------------------------------------------------------------------------
  // DUT key-width parameter (override via +define+KEY_BITS=N at compile time)
  // ---------------------------------------------------------------------------
`ifndef KEY_BITS
  `define KEY_BITS 128
`endif
  localparam int TB_KEY_BITS = `KEY_BITS;

  // ---------------------------------------------------------------------------
  // Clock and reset
  // ---------------------------------------------------------------------------
  logic clk;
  logic rst_n;

  // 10 ns period → 100 MHz
  initial clk = 1'b0;
  always #5ns clk = ~clk;

  // Reset: assert for 10 cycles, then release
  initial begin
    rst_n = 1'b0;
    repeat (10) @(posedge clk);
    @(negedge clk);   // deassert on falling edge for clean setup
    rst_n = 1'b1;
    `uvm_info("TB_TOP", "Reset deasserted", UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Virtual interface instantiation
  // ---------------------------------------------------------------------------
  aes_if dut_if (.clk(clk), .rst_n(rst_n));

  // ---------------------------------------------------------------------------
  // DUT instantiation — KEY_BITS from compile-time define
  // ---------------------------------------------------------------------------
  aes_top #(
    .KEY_BITS (TB_KEY_BITS)
  ) dut (
    .clk          (clk),
    .rst_n        (rst_n),

    // Key management
    .s_key_in     (dut_if.s_key_in[TB_KEY_BITS-1:0]),
    .s_key_expand (dut_if.s_key_expand),
    .key_ready    (dut_if.key_ready),

    // IV / nonce
    .s_iv         (dut_if.s_iv),
    .s_iv_load    (dut_if.s_iv_load),

    // Input stream
    .s_valid      (dut_if.s_valid),
    .s_ready      (dut_if.s_ready),
    .s_data       (dut_if.s_data),
    .s_mode       (dut_if.s_mode),
    .s_dir        (dut_if.s_dir),
    .s_tag        (dut_if.s_tag),

    // Output stream
    .m_valid      (dut_if.m_valid),
    .m_ready      (dut_if.m_ready),
    .m_data       (dut_if.m_data),
    .m_tag        (dut_if.m_tag),
    .m_err        (dut_if.m_err)
  );

  // ---------------------------------------------------------------------------
  // UVM config_db: register virtual interface
  // ---------------------------------------------------------------------------
  initial begin
    uvm_config_db #(virtual aes_if)::set(
      null,          // from context (global)
      "uvm_test_top.*",
      "vif",
      dut_if
    );

    // Also register key_bits for tests that need to know it
    uvm_config_db #(int)::set(
      null,
      "uvm_test_top.*",
      "key_bits",
      TB_KEY_BITS
    );

    `uvm_info("TB_TOP",
      $sformatf("DUT KEY_BITS = %0d, vif registered in config_db", TB_KEY_BITS),
      UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Simulation timeout watchdog (prevents infinite hang on protocol errors)
  // ---------------------------------------------------------------------------
  initial begin
    // Allow enough time for stress test (200 txns × ~50 cycles × 10 ns)
    #500us;
    `uvm_fatal("WATCHDOG", "Simulation timeout — check for protocol deadlock")
  end

  // ---------------------------------------------------------------------------
  // Waveform dump (uncomment for VCD/FSDB capture)
  // ---------------------------------------------------------------------------
  // initial begin
  //   $dumpfile("aes_tb.vcd");
  //   $dumpvars(0, aes_tb_top);
  // end

  // ---------------------------------------------------------------------------
  // Start UVM test
  // ---------------------------------------------------------------------------
  initial begin
    run_test();
  end

endmodule : aes_tb_top
