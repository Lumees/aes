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
// AES UVM Testbench — Virtual Interface
// =============================================================================
// Provides a SystemVerilog interface wrapping all aes_top ports.
// KEY_BITS is fixed to 128 here; aes_tb_top uses a generate/parameter approach
// to bind wider keys. For a parameterized interface instantiation use the
// localparam below and regenerate the interface at the top level.
// =============================================================================

`timescale 1ns/1ps

interface aes_if (input logic clk, input logic rst_n);

  import aes_pkg::*;

  // ---------------------------------------------------------------------------
  // Interface-local key width — set via localparam so the interface compiles
  // standalone. The TB top overrides by picking the matching interface width.
  // ---------------------------------------------------------------------------
  localparam int KEY_BITS = 128;

  // ---------------------------------------------------------------------------
  // DUT ports (all driven/sampled here)
  // ---------------------------------------------------------------------------

  // Key management
  logic [KEY_BITS-1:0]  s_key_in;
  logic                  s_key_expand;
  logic                  key_ready;

  // IV / nonce
  logic [127:0]          s_iv;
  logic                  s_iv_load;

  // Input stream
  logic                  s_valid;
  logic                  s_ready;
  logic [127:0]          s_data;
  mode_t                 s_mode;
  dir_t                  s_dir;
  logic [7:0]            s_tag;

  // Output stream
  logic                  m_valid;
  logic                  m_ready;
  logic [127:0]          m_data;
  logic [7:0]            m_tag;
  logic                  m_err;

  // ---------------------------------------------------------------------------
  // Driver clocking block (active driving on posedge; sample 1-step before edge)
  // ---------------------------------------------------------------------------
  clocking driver_cb @(posedge clk);
    default input  #1step
            output #1step;

    // Key management — driven by driver
    output s_key_in;
    output s_key_expand;
    input  key_ready;

    // IV
    output s_iv;
    output s_iv_load;

    // Input stream
    output s_valid;
    input  s_ready;
    output s_data;
    output s_mode;
    output s_dir;
    output s_tag;

    // Output stream — driver reads back response
    input  m_valid;
    output m_ready;
    input  m_data;
    input  m_tag;
    input  m_err;
  endclocking : driver_cb

  // ---------------------------------------------------------------------------
  // Monitor clocking block (passive — only inputs)
  // ---------------------------------------------------------------------------
  clocking monitor_cb @(posedge clk);
    default input #1step;

    input s_key_in;
    input s_key_expand;
    input key_ready;

    input s_iv;
    input s_iv_load;

    input s_valid;
    input s_ready;
    input s_data;
    input s_mode;
    input s_dir;
    input s_tag;

    input m_valid;
    input m_ready;
    input m_data;
    input m_tag;
    input m_err;
  endclocking : monitor_cb

  // ---------------------------------------------------------------------------
  // Modports
  // ---------------------------------------------------------------------------
  modport driver_mp  (clocking driver_cb,  input clk, input rst_n);
  modport monitor_mp (clocking monitor_cb, input clk, input rst_n);

endinterface : aes_if
