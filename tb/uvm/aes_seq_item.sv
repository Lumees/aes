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
// AES UVM Testbench — Sequence Item
// =============================================================================
// Represents one complete AES block-cipher operation (stimulus + response).
// =============================================================================

`ifndef AES_SEQ_ITEM_SV
`define AES_SEQ_ITEM_SV

`include "uvm_macros.svh"

class aes_seq_item extends uvm_sequence_item;

  import aes_pkg::*;

  `uvm_object_utils_begin(aes_seq_item)
    `uvm_field_int        (key,       UVM_ALL_ON | UVM_HEX)
    `uvm_field_int        (key_bits,  UVM_ALL_ON | UVM_DEC)
    `uvm_field_int        (iv,        UVM_ALL_ON | UVM_HEX)
    `uvm_field_int        (plaintext, UVM_ALL_ON | UVM_HEX)
    `uvm_field_enum       (mode_t,  mode,      UVM_ALL_ON)
    `uvm_field_enum       (dir_t,   direction, UVM_ALL_ON)
    `uvm_field_int        (tag,       UVM_ALL_ON | UVM_HEX)
    `uvm_field_int        (result,    UVM_ALL_ON | UVM_HEX)
    `uvm_field_int        (err,       UVM_ALL_ON | UVM_BIN)
  `uvm_object_utils_end

  // -------------------------------------------------------------------------
  // Stimulus fields (randomised)
  // -------------------------------------------------------------------------
  rand logic [255:0]      key;           // full 256-bit container; lower bytes used
  rand int unsigned       key_bits;      // 128 | 192 | 256
  rand logic [127:0]      iv;            // IV / nonce for CBC and CTR
  rand logic [127:0]      plaintext;     // input block (encrypt) or ciphertext (decrypt)
  rand mode_t             mode;          // ECB | CBC | CTR
  rand dir_t              direction;     // ENCRYPT | DECRYPT
  rand logic [7:0]        tag;           // side-band tag carried through pipeline

  // -------------------------------------------------------------------------
  // Response fields (filled by driver after DUT responds)
  // -------------------------------------------------------------------------
  logic [127:0]           result;        // DUT output block
  logic                   err;           // DUT m_err flag

  // -------------------------------------------------------------------------
  // Constraints
  // -------------------------------------------------------------------------

  // Key length: equal probability for each supported size
  constraint c_key_bits {
    key_bits inside {128, 192, 256};
    key_bits dist { 128 := 50, 192 := 25, 256 := 25 };
  }

  // Mode distribution — ECB weighted heavier for easier scoreboard checking
  constraint c_mode {
    mode dist { ECB := 50, CBC := 25, CTR := 25 };
  }

  // Direction distribution — equal encrypt/decrypt
  constraint c_dir {
    direction dist { ENCRYPT := 50, DECRYPT := 50 };
  }

  // Key upper bits beyond key_bits must be zero (cleanliness)
  constraint c_key_upper_zero {
    (key_bits == 128) -> key[255:128] == '0;
    (key_bits == 192) -> key[255:192] == '0;
  }

  // Avoid all-zero key (trivially weak)
  constraint c_key_nonzero {
    key != '0;
  }

  // Avoid all-zero plaintext occasionally (keep some diversity but allow it)
  constraint c_pt_distribution {
    plaintext dist {
      128'h0                  := 2,
      128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF := 2,
      [128'h1 : 128'hFFFE]   := 96
    };
  }

  // Tag: full 8-bit space
  constraint c_tag {
    tag dist { 8'h00 := 5, 8'hFF := 5, [8'h01:8'hFE] := 90 };
  }

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------
  function new(string name = "aes_seq_item");
    super.new(name);
  endfunction : new

  // -------------------------------------------------------------------------
  // Convenience: return the active portion of the key for the selected width
  // -------------------------------------------------------------------------
  function logic [255:0] get_active_key();
    case (key_bits)
      128: return {128'b0, key[127:0]};
      192: return {64'b0,  key[191:0]};
      256: return key;
      default: return key;
    endcase
  endfunction : get_active_key

  // Short printable summary
  function string convert2string();
    return $sformatf(
      "AES-%-3d %s %s | pt=%h | key=%h | iv=%h | tag=0x%02h | result=%h | err=%0b",
      key_bits,
      mode.name(),
      direction.name(),
      plaintext,
      key[key_bits-1:0],
      iv,
      tag,
      result,
      err
    );
  endfunction : convert2string

endclass : aes_seq_item

`endif // AES_SEQ_ITEM_SV
