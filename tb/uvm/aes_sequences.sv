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
// AES UVM Testbench — Sequences
// =============================================================================
// All sequences in one file.  Each sequence:
//   1. Randomises (or hard-codes) a seq_item
//   2. Starts it on the sequencer
//   3. Writes the full item (with key/iv) to env.ap_context so the scoreboard
//      reference model has key and IV available.
//
// Sequences access ap_context through the p_sequencer or via a direct handle
// set in the test's build_phase.
// =============================================================================

`ifndef AES_SEQUENCES_SV
`define AES_SEQUENCES_SV

`include "uvm_macros.svh"

// ============================================================================
// Base sequence
// ============================================================================
class aes_base_seq extends uvm_sequence #(aes_seq_item);

  import aes_pkg::*;

  `uvm_object_utils(aes_base_seq)

  // Handle to the env's context analysis port — set by test before starting
  uvm_analysis_port #(aes_seq_item) ap_context;

  function new(string name = "aes_base_seq");
    super.new(name);
  endfunction : new

  // Helper: send one item and publish context
  task send_item(aes_seq_item item);
    start_item(item);
    if (!item.randomize())
      `uvm_fatal("SEQ_RAND", "Failed to randomise seq_item")
    finish_item(item);

    // Publish full item so scoreboard reference model has key + iv
    if (ap_context != null)
      ap_context.write(item);
    else
      `uvm_warning("SEQ_CTX", "ap_context handle is null — scoreboard may not have key/iv")
  endtask : send_item

  // Helper: send a pre-built (non-randomised) item directly
  task send_fixed_item(aes_seq_item item);
    start_item(item);
    finish_item(item);
    if (ap_context != null)
      ap_context.write(item);
    else
      `uvm_warning("SEQ_CTX", "ap_context handle is null — scoreboard may not have key/iv")
  endtask : send_fixed_item

  virtual task body();
    `uvm_warning("SEQ", "aes_base_seq::body() called — override in derived class")
  endtask : body

endclass : aes_base_seq


// ============================================================================
// NIST ECB sequences (hardcoded vectors)
// ============================================================================

// Helper to build a fixed ECB seq_item
class aes_nist_ecb_seq extends aes_base_seq;

  `uvm_object_utils(aes_nist_ecb_seq)

  function new(string name = "aes_nist_ecb_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    aes_seq_item item;

    // ----------------------------------------------------------------
    // NIST AES-128 ECB Encrypt
    // FIPS 197 Appendix B
    // Key : 2b7e151628aed2a6abf7158809cf4f3c
    // PT  : 3243f6a8885a308d313198a2e0370734
    // CT  : 3925841d02dc09fbdc118597196a0b32
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist128_enc");
    item.key       = 256'h0000_0000_0000_0000_0000_0000_0000_0000_2b7e1516_28aed2a6_abf71588_09cf4f3c;
    item.key_bits  = 128;
    item.iv        = '0;
    item.plaintext = 128'h3243f6a8_885a308d_313198a2_e0370734;
    item.mode      = ECB;
    item.direction = ENCRYPT;
    item.tag       = 8'hA0;
    `uvm_info("SEQ_NIST", "Sending NIST AES-128 ECB Encrypt", UVM_MEDIUM)
    send_fixed_item(item);

    // ----------------------------------------------------------------
    // NIST AES-128 ECB Decrypt (same key/block, verify round-trip)
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist128_dec");
    item.key       = 256'h0000_0000_0000_0000_0000_0000_0000_0000_2b7e1516_28aed2a6_abf71588_09cf4f3c;
    item.key_bits  = 128;
    item.iv        = '0;
    item.plaintext = 128'h3925841d_02dc09fb_dc118597_196a0b32;  // CT as input to decrypt
    item.mode      = ECB;
    item.direction = DECRYPT;
    item.tag       = 8'hA1;
    `uvm_info("SEQ_NIST", "Sending NIST AES-128 ECB Decrypt", UVM_MEDIUM)
    send_fixed_item(item);

    // ----------------------------------------------------------------
    // NIST AES-192 ECB Encrypt
    // Key : 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    // PT  : 6bc1bee22e409f96e93d7e117393172a
    // CT  : bd334f1d6e45f25ff712a214571fa5cc
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist192_enc");
    item.key       = 256'h0000_0000_0000_0000_8e73b0f7_da0e6452_c810f32b_809079e5_62f8ead2_522c6b7b;
    item.key_bits  = 192;
    item.iv        = '0;
    item.plaintext = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
    item.mode      = ECB;
    item.direction = ENCRYPT;
    item.tag       = 8'hB0;
    `uvm_info("SEQ_NIST", "Sending NIST AES-192 ECB Encrypt", UVM_MEDIUM)
    send_fixed_item(item);

    // ----------------------------------------------------------------
    // NIST AES-256 ECB Encrypt
    // Key : 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    // PT  : 6bc1bee22e409f96e93d7e117393172a
    // CT  : f3eed1bdb5d2a03c064b5a7e3db181f8
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist256_enc");
    item.key       = 256'h603deb10_15ca71be_2b73aef0_857d7781_1f352c07_3b6108d7_2d9810a3_0914dff4;
    item.key_bits  = 256;
    item.iv        = '0;
    item.plaintext = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
    item.mode      = ECB;
    item.direction = ENCRYPT;
    item.tag       = 8'hC0;
    `uvm_info("SEQ_NIST", "Sending NIST AES-256 ECB Encrypt", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : aes_nist_ecb_seq


// ============================================================================
// NIST CBC sequence
// ============================================================================
class aes_nist_cbc_seq extends aes_base_seq;

  `uvm_object_utils(aes_nist_cbc_seq)

  function new(string name = "aes_nist_cbc_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    aes_seq_item item;

    // ----------------------------------------------------------------
    // NIST AES-128 CBC Encrypt
    // Key : 2b7e151628aed2a6abf7158809cf4f3c
    // IV  : 000102030405060708090a0b0c0d0e0f
    // PT  : 6bc1bee22e409f96e93d7e117393172a
    // CT  : 7649abac8119b246cee98e9b12e9197d
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist128_cbc_enc");
    item.key       = 256'h0000_0000_0000_0000_0000_0000_0000_0000_2b7e1516_28aed2a6_abf71588_09cf4f3c;
    item.key_bits  = 128;
    item.iv        = 128'h00010203_04050607_08090a0b_0c0d0e0f;
    item.plaintext = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
    item.mode      = CBC;
    item.direction = ENCRYPT;
    item.tag       = 8'hD0;
    `uvm_info("SEQ_NIST", "Sending NIST AES-128 CBC Encrypt", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : aes_nist_cbc_seq


// ============================================================================
// NIST CTR sequence
// ============================================================================
class aes_nist_ctr_seq extends aes_base_seq;

  `uvm_object_utils(aes_nist_ctr_seq)

  function new(string name = "aes_nist_ctr_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    aes_seq_item item;

    // ----------------------------------------------------------------
    // NIST AES-128 CTR Encrypt
    // Key : 2b7e151628aed2a6abf7158809cf4f3c
    // IV  : f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // PT  : 6bc1bee22e409f96e93d7e117393172a
    // CT  : 874d6191b620e3261bef6864990db6ce
    // ----------------------------------------------------------------
    item = aes_seq_item::type_id::create("nist128_ctr");
    item.key       = 256'h0000_0000_0000_0000_0000_0000_0000_0000_2b7e1516_28aed2a6_abf71588_09cf4f3c;
    item.key_bits  = 128;
    item.iv        = 128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff;
    item.plaintext = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
    item.mode      = CTR;
    item.direction = ENCRYPT;
    item.tag       = 8'hE0;
    `uvm_info("SEQ_NIST", "Sending NIST AES-128 CTR Encrypt", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : aes_nist_ctr_seq


// ============================================================================
// Random ECB sequence
// ============================================================================
class aes_random_ecb_seq extends aes_base_seq;

  `uvm_object_utils(aes_random_ecb_seq)

  int unsigned num_transactions = 20;

  function new(string name = "aes_random_ecb_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    aes_seq_item item;

    repeat (num_transactions) begin
      item = aes_seq_item::type_id::create("rand_ecb");
      start_item(item);
      // Constrain to ECB only
      if (!item.randomize() with { mode == ECB; })
        `uvm_fatal("SEQ_RAND", "Failed to randomise ECB seq_item")
      finish_item(item);
      if (ap_context != null) ap_context.write(item);
    end

    `uvm_info("SEQ_RAND_ECB",
      $sformatf("Completed %0d random ECB transactions", num_transactions),
      UVM_MEDIUM)
  endtask : body

endclass : aes_random_ecb_seq


// ============================================================================
// Random all-modes sequence
// ============================================================================
class aes_random_all_modes_seq extends aes_base_seq;

  `uvm_object_utils(aes_random_all_modes_seq)

  int unsigned num_transactions = 20;

  function new(string name = "aes_random_all_modes_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    aes_seq_item item;

    repeat (num_transactions) begin
      item = aes_seq_item::type_id::create("rand_all");
      send_item(item);
    end

    `uvm_info("SEQ_RAND_ALL",
      $sformatf("Completed %0d random mixed-mode transactions", num_transactions),
      UVM_MEDIUM)
  endtask : body

endclass : aes_random_all_modes_seq

`endif // AES_SEQUENCES_SV
