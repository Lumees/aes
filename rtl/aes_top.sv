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
// AES IP - Top Level
// =============================================================================
// Combines key expansion, pipelined core, and block-cipher mode control.
//
// Supported modes (s_mode):
//   ECB : Each block encrypted/decrypted independently. Fully pipelined.
//   CBC : Encrypt: c_i = E(p_i ^ c_{i-1}), c_0 = IV. One block per PIPE_LAT.
//         Decrypt: p_i = D(c_i) ^ c_{i-1}. Fully pipelined.
//   CTR : p_i = c_i ^ E(IV || ctr_i). Fully pipelined (only enc pipeline used).
//
// Interface:
//   s_valid / s_ready : handshake. s_ready = 0 during key expansion and
//                       during CBC-encrypt busy (feedback stall).
//   s_key_in          : key to expand (write before asserting s_key_expand)
//   s_key_expand      : pulse to trigger key expansion
//   s_iv              : IV / nonce (registered; valid until next s_iv_load)
//   s_iv_load         : pulse to latch s_iv
//   m_valid / m_ready : output handshake (m_ready is informational; the pipeline
//                       does not stall — use AXI4-Stream wrapper for backpressure)
//   m_err             : asserted when a block is sent before key is ready
//
// Latency : PIPE_LAT = NR + 1 cycles from s_valid to m_valid
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_top #(
  parameter int KEY_BITS = aes_pkg::KEY_BITS,
  // Derived from KEY_BITS — DO NOT override
  parameter int NR = (KEY_BITS == 128) ? 10 : (KEY_BITS == 192) ? 12 : 14
) (
  input  logic                 clk,
  input  logic                 rst_n,

  // ── Key management ─────────────────────────────────────────────────────────
  input  logic [KEY_BITS-1:0]  s_key_in,
  input  logic                 s_key_expand,  // pulse: start key schedule
  output logic                 key_ready,     // 1 once key expanded

  // ── IV / nonce ─────────────────────────────────────────────────────────────
  input  logic [127:0]         s_iv,
  input  logic                 s_iv_load,     // pulse: latch IV

  // ── Input stream ───────────────────────────────────────────────────────────
  input  logic                 s_valid,
  output logic                 s_ready,
  input  logic [127:0]         s_data,        // plaintext (enc) or ciphertext (dec)
  input  mode_t                s_mode,        // ECB | CBC | CTR
  input  dir_t                 s_dir,         // ENCRYPT | DECRYPT
  input  logic [7:0]           s_tag,

  // ── Output stream ──────────────────────────────────────────────────────────
  output logic                 m_valid,
  input  logic                 m_ready,
  output logic [127:0]         m_data,        // ciphertext (enc) or plaintext (dec)
  output logic [7:0]           m_tag,
  output logic                 m_err          // key not ready when block submitted
);

  // ── Round keys from key expander ───────────────────────────────────────────
  logic [127:0] round_keys [0:NR];

  aes_key_expand #(.KEY_BITS(KEY_BITS)) u_key_expand (
    .clk        (clk),
    .rst_n      (rst_n),
    .key_in     (s_key_in),
    .key_expand (s_key_expand),
    .round_keys (round_keys),
    .key_ready  (key_ready)
  );

  // ── IV / counter register ─────────────────────────────────────────────────
  logic [127:0] iv_reg;
  logic [127:0] ctr;          // counter for CTR mode (incremented per block)

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      iv_reg <= '0;
    end else if (s_iv_load) begin
      iv_reg <= s_iv;
    end
  end

  // ── CBC feedback registers ────────────────────────────────────────────────
  logic [127:0] cbc_prev;       // CBC-encrypt: CT[i-1] to XOR before core
  logic [127:0] cbc_dec_prev;   // CBC-decrypt: CT[i-1] to XOR after core
  logic         cbc_enc_busy;   // stall: waiting for CBC-encrypt output

  // ── Core input mux ────────────────────────────────────────────────────────
  logic [127:0] core_data_in;
  dir_t         core_dir;

  always_comb begin
    core_dir = s_dir;
    unique case (s_mode)
      ECB: core_data_in = s_data;
      CBC: core_data_in = (s_dir == ENCRYPT) ? (s_data ^ cbc_prev) : s_data;
      CTR: begin
        // CTR always uses encryption of counter
        core_data_in = ctr;
        core_dir     = ENCRYPT;
      end
      default: core_data_in = s_data;
    endcase
  end

  // ── s_ready logic ─────────────────────────────────────────────────────────
  // Not ready during: key expansion, CBC-encrypt busy (feedback stall)
  assign s_ready = key_ready && !cbc_enc_busy;

  // ── Fire into the core ────────────────────────────────────────────────────
  logic         core_valid_in;
  logic [7:0]   core_tag_in;
  assign core_valid_in = s_valid && s_ready;
  assign core_tag_in   = s_tag;

  // ── Mode metadata pipeline (PIPE_LAT deep, same timing as core) ───────────
  // Carry mode, dir, original s_data (for CBC/CTR XOR on output) through pipeline
  typedef struct packed {
    logic         valid;
    logic [7:0]   tag;
    mode_t        mode;
    dir_t         dir;
    logic [127:0] prev_ct;   // CBC decrypt: previous CT; CTR: keystream XOR
  } meta_t;

  meta_t meta_pipe [0:NR];

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      meta_pipe[0] <= '0;
    end else begin
      meta_pipe[0].valid   <= core_valid_in;
      meta_pipe[0].tag     <= core_tag_in;
      meta_pipe[0].mode    <= s_mode;
      meta_pipe[0].dir     <= s_dir;
      // CTR: carry data (for E(ctr)^data XOR at output)
      // CBC-enc: carry cbc_prev (for cbc_prev update tracking, not used for XOR)
      // CBC-dec: carry cbc_dec_prev (CT[i-1] for PT = D(CT[i]) ^ CT[i-1])
      meta_pipe[0].prev_ct <= (s_mode == CTR)                    ? s_data :
                               (s_mode == CBC && s_dir == DECRYPT) ? cbc_dec_prev :
                               cbc_prev;
    end
  end

  genvar mi;
  generate
    for (mi = 1; mi <= NR; mi++) begin : gen_meta
      always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) meta_pipe[mi] <= '0;
        else        meta_pipe[mi] <= meta_pipe[mi-1];
      end
    end
  endgenerate

  // ── AES core ──────────────────────────────────────────────────────────────
  logic         core_m_valid;
  logic [127:0] core_m_data;
  logic [7:0]   core_m_tag;
  dir_t         core_m_dir;

  aes_core #(.KEY_BITS(KEY_BITS)) u_core (
    .clk        (clk),
    .rst_n      (rst_n),
    .s_valid    (core_valid_in),
    .s_data     (core_data_in),
    .s_tag      (core_tag_in),
    .s_dir      (core_dir),
    .round_keys (round_keys),
    .m_valid    (core_m_valid),
    .m_data     (core_m_data),
    .m_tag      (core_m_tag),
    .m_dir      (core_m_dir)
  );

  // ── Output post-processing (CBC/CTR XOR) ─────────────────────────────────
  // Metadata at pipeline output is meta_pipe[NR]
  logic [127:0] post_data;

  always_comb begin
    unique case (meta_pipe[NR].mode)
      ECB: post_data = core_m_data;
      CBC: post_data = (meta_pipe[NR].dir == ENCRYPT)
                         ? core_m_data                             // CT out
                         : core_m_data ^ meta_pipe[NR].prev_ct; // PT = D(CT) ^ prev_CT
      CTR: post_data = core_m_data ^ meta_pipe[NR].prev_ct; // PT/CT = E(CTR) ^ data
      default: post_data = core_m_data;
    endcase
  end

  assign m_valid = core_m_valid;
  assign m_data  = post_data;
  assign m_tag   = core_m_tag;
  assign m_err   = core_valid_in && !key_ready;  // sticky via register in wrapper

  // ── CBC feedback update ───────────────────────────────────────────────────
  // CBC encrypt: cbc_prev ← ciphertext output of previous block
  // CBC decrypt: cbc_prev ← ciphertext input of previous block (carried in pipe)
  // Stall after CBC-encrypt submission until output arrives
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      cbc_prev     <= '0;
      cbc_dec_prev <= '0;
      cbc_enc_busy <= 1'b0;
      ctr          <= '0;
    end else begin
      // Stall on CBC-encrypt: busy from submission until output
      // Use s_mode (current input), not meta_pipe[0].mode (registered previous cycle)
      if (core_valid_in && s_mode == CBC && s_dir == ENCRYPT)
        cbc_enc_busy <= 1'b1;
      if (core_m_valid && meta_pipe[NR].mode == CBC)
        cbc_enc_busy <= 1'b0;

      // CBC-encrypt: update cbc_prev to new ciphertext after each encrypted block
      if (core_m_valid && meta_pipe[NR].mode == CBC &&
          meta_pipe[NR].dir == ENCRYPT)
        cbc_prev <= post_data;

      // CBC-decrypt: update cbc_dec_prev to the CT just processed (s_data at submission)
      // On submission: carry s_data forward so next block knows CT[i-1]
      if (core_valid_in && s_mode == CBC && s_dir == DECRYPT)
        cbc_dec_prev <= s_data;

      // CTR: increment counter after each block submitted
      // Use s_mode (current), not meta_pipe[0].mode (previous cycle)
      if (core_valid_in && s_mode == CTR)
        ctr <= ctr + 1;

      // IV load resets CBC feedback to IV and loads CTR
      if (s_iv_load) begin
        cbc_prev     <= s_iv;   // CBC-enc first block XORs with IV
        cbc_dec_prev <= s_iv;   // CBC-dec first block XORs with IV
        cbc_enc_busy <= 1'b0;
        ctr          <= s_iv;   // CTR mode starts at IV
      end
    end
  end

endmodule : aes_top
