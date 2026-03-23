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
// AES UVM Testbench — Functional Coverage Collector
// =============================================================================
// Subscribes to the output monitor analysis port.
// Covergroups:
//   cg_aes  : key size × mode × direction (with cross)
//   cg_data : plaintext data pattern bins
// =============================================================================

`ifndef AES_COVERAGE_SV
`define AES_COVERAGE_SV

`include "uvm_macros.svh"

class aes_coverage extends uvm_subscriber #(aes_seq_item);

  import aes_pkg::*;

  `uvm_component_utils(aes_coverage)

  // Current sampled item fields (written in write() before sampling)
  int unsigned  cov_key_bits;
  mode_t        cov_mode;
  dir_t         cov_dir;
  logic [127:0] cov_data;
  logic [127:0] cov_result;
  logic         cov_err;

  // ---------------------------------------------------------------------------
  // Covergroup: AES configuration space
  // ---------------------------------------------------------------------------
  covergroup cg_aes;
    option.per_instance = 1;
    option.name         = "cg_aes";
    option.comment      = "AES key-size / mode / direction coverage";

    cp_key_bits: coverpoint cov_key_bits {
      bins k128 = {128};
      bins k192 = {192};
      bins k256 = {256};
    }

    cp_mode: coverpoint cov_mode {
      bins ecb = {ECB};
      bins cbc = {CBC};
      bins ctr = {CTR};
    }

    cp_dir: coverpoint cov_dir {
      bins enc = {ENCRYPT};
      bins dec = {DECRYPT};
    }

    // Cross: mode × direction (all 6 combinations required)
    cx_mode_dir: cross cp_mode, cp_dir;

    // Cross: key-bits × mode
    cx_key_mode: cross cp_key_bits, cp_mode;

    // Error cases (should be zero in a clean run, but covered for completeness)
    cp_err: coverpoint cov_err {
      bins no_err = {0};
      bins err    = {1};
    }
  endgroup : cg_aes

  // ---------------------------------------------------------------------------
  // Covergroup: data pattern coverage (plaintext / input block)
  // ---------------------------------------------------------------------------
  covergroup cg_data;
    option.per_instance = 1;
    option.name         = "cg_data";
    option.comment      = "AES input data pattern coverage";

    cp_data_pattern: coverpoint cov_data {
      bins all_zeros      = {128'h0};
      bins all_ones       = {128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF};
      bins low_range      = { [128'h0000_0001 : 128'h0000_FFFF] };
      bins mid_range_low  = { [128'h0001_0000 : 128'h7FFF_FFFF] };
      bins mid_range_high = { [128'h8000_0000 : 128'hFFFE_FFFF] };
      bins high_range     = { [128'hFFFF_0000 : 128'hFFFF_FFFE] };
      bins other          = default;
    }

    // Result data pattern (output distribution)
    cp_result_pattern: coverpoint cov_result {
      bins all_zeros  = {128'h0};
      bins all_ones   = {128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF};
      bins other      = default;
    }
  endgroup : cg_data

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------
  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg_aes  = new();
    cg_data = new();
  endfunction : new

  `uvm_component_utils_begin(aes_coverage)
  `uvm_component_utils_end

  // ---------------------------------------------------------------------------
  // write(): called by analysis port on each output transaction
  // ---------------------------------------------------------------------------
  function void write(aes_seq_item t);
    cov_key_bits = t.key_bits;
    cov_mode     = t.mode;
    cov_dir      = t.direction;
    cov_data     = t.plaintext;
    cov_result   = t.result;
    cov_err      = t.err;

    cg_aes.sample();
    cg_data.sample();

    `uvm_info("COV",
      $sformatf("Sampled: key_bits=%0d mode=%s dir=%s",
        cov_key_bits, cov_mode.name(), cov_dir.name()),
      UVM_DEBUG)
  endfunction : write

  // ---------------------------------------------------------------------------
  // report_phase: print coverage summary
  // ---------------------------------------------------------------------------
  function void report_phase(uvm_phase phase);
    `uvm_info("COV_REPORT",
      $sformatf("cg_aes  coverage: %.2f%%", cg_aes.get_coverage()),
      UVM_NONE)
    `uvm_info("COV_REPORT",
      $sformatf("cg_data coverage: %.2f%%", cg_data.get_coverage()),
      UVM_NONE)
  endfunction : report_phase

endclass : aes_coverage

`endif // AES_COVERAGE_SV
