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
// =============================================================================
// AES IP - Key Expansion (Key Schedule)
// =============================================================================
// Iteratively expands the user key into N_ROUND_KEYS × 128-bit round keys.
//
// Latency: TOTAL_KEY_WORDS clock cycles after key_expand pulse
//   AES-128: 44 cycles   AES-192: 52 cycles   AES-256: 60 cycles
//
// Usage:
//   1. Write key to key_in[KEY_BITS-1:0]
//   2. Assert key_expand for one clock
//   3. Wait for key_ready to assert
//   4. round_keys[0..N_ROUNDS] are stable until next key_expand
//
// round_keys[0] = original key (initial AddRoundKey)
// round_keys[1..N_ROUNDS] = expanded round keys
// round_keys are indexed [0:N_ROUNDS], each 128 bits wide
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_key_expand #(
  parameter int KEY_BITS = aes_pkg::KEY_BITS,
  // Derived from KEY_BITS — DO NOT override
  parameter int NR  = (KEY_BITS == 128) ? 10 : (KEY_BITS == 192) ? 12 : 14,
  parameter int NKW = KEY_BITS / 32,
  parameter int NW  = 4 * ((KEY_BITS == 128) ? 11 : (KEY_BITS == 192) ? 13 : 15)
) (
  input  logic                   clk,
  input  logic                   rst_n,

  input  logic [KEY_BITS-1:0]    key_in,
  input  logic                   key_expand,   // pulse: start expansion

  output logic [127:0]           round_keys [0:NR],
  output logic                   key_ready
);

  // ---------------------------------------------------------------------------
  // Word-expanded key schedule storage
  // ---------------------------------------------------------------------------
  logic [31:0] W [0:NW-1];    // full expanded schedule
  logic [31:0] W_next;

  // Expansion FSM
  logic [$clog2(NW+1)-1:0] idx;   // word index being computed
  logic busy;

  // ---------------------------------------------------------------------------
  // SubWord: apply S-box to each byte of a 32-bit word
  // ---------------------------------------------------------------------------
  function automatic logic [31:0] sub_word(input logic [31:0] w);
    return {sbox_fwd(w[31:24]), sbox_fwd(w[23:16]),
            sbox_fwd(w[15: 8]), sbox_fwd(w[ 7: 0])};
  endfunction

  // RotWord: rotate 32-bit word left by 8 bits
  function automatic logic [31:0] rot_word(input logic [31:0] w);
    return {w[23:0], w[31:24]};
  endfunction

  // ---------------------------------------------------------------------------
  // Key schedule FSM
  // ---------------------------------------------------------------------------
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      busy      <= 0;
      key_ready <= 0;
      idx       <= 0;
      for (int i = 0; i < NW; i++) W[i] <= '0;
    end else begin

      if (key_expand && !busy) begin
        // Load the initial key words
        for (int i = 0; i < NKW; i++)
          W[i] <= key_in[KEY_BITS-1 - 32*i -: 32];
        idx       <= NKW;
        busy      <= 1;
        key_ready <= 0;
      end

      if (busy) begin
        automatic logic [31:0] temp;
        automatic int          i_int;
        i_int = int'(idx);

        temp = W[i_int - 1];

        if (i_int % NKW == 0)
          temp = sub_word(rot_word(temp)) ^ {rcon(i_int / NKW), 24'h0};
        else if (NKW > 6 && i_int % NKW == 4)
          temp = sub_word(temp);

        W[i_int] <= W[i_int - NKW] ^ temp;

        if (idx == NW - 1) begin
          busy      <= 0;
          key_ready <= 1;
          idx       <= 0;
        end else begin
          idx <= idx + 1;
        end
      end

    end
  end

  // ---------------------------------------------------------------------------
  // Pack W[] words into 128-bit round_keys[]
  // round_keys[k] = {W[4k], W[4k+1], W[4k+2], W[4k+3]}
  // ---------------------------------------------------------------------------
  always_comb begin
    for (int k = 0; k <= NR; k++)
      round_keys[k] = {W[4*k], W[4*k+1], W[4*k+2], W[4*k+3]};
  end

endmodule : aes_key_expand
