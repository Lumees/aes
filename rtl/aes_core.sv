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
// AES IP - Pipelined Core (Encrypt + Decrypt)
// =============================================================================
// Instantiates two fully-pipelined datapaths:
//   enc_pipe[0..NR] : encryption (SubBytes→ShiftRows→MixColumns→ARK)
//   dec_pipe[0..NR] : decryption (InvShiftRows→InvSubBytes→ARK→InvMixCols)
//
// Both pipelines run continuously. The caller selects which output to use via
// s_dir. Each pipeline produces m_valid NR+1 cycles after s_valid.
//
// Tag and direction are propagated through both pipelines so the output side
// knows which result to forward.
//
// Throughput : 1 block/clock per direction (2 independent streams possible)
// Latency    : NR + 1 = PIPE_LAT cycles
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_core #(
  parameter int KEY_BITS = aes_pkg::KEY_BITS,
  // Derived from KEY_BITS — DO NOT override
  parameter int NR = (KEY_BITS == 128) ? 10 : (KEY_BITS == 192) ? 12 : 14
) (
  input  logic         clk,
  input  logic         rst_n,

  // Input
  input  logic         s_valid,
  input  logic [127:0] s_data,
  input  logic [7:0]   s_tag,
  input  dir_t         s_dir,    // ENCRYPT | DECRYPT

  // Pre-expanded round keys (from aes_key_expand)
  input  logic [127:0] round_keys [0:NR],

  // Output — valid NR+1 cycles after s_valid
  output logic         m_valid,
  output logic [127:0] m_data,
  output logic [7:0]   m_tag,
  output dir_t         m_dir
);

  // ── Pipeline structs ───────────────────────────────────────────────────────
  // Carry dir through the pipe so output mux knows which datapath fired
  typedef struct packed {
    logic         valid;
    logic [7:0]   tag;
    dir_t         dir;
    logic [127:0] data;
  } pipe_t;

  // ── Encryption pipeline ────────────────────────────────────────────────────
  pipe_t enc_pipe [0:NR];

  // Stage 0: Initial AddRoundKey
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) enc_pipe[0] <= '0;
    else begin
      enc_pipe[0].valid <= s_valid && (s_dir == ENCRYPT);
      enc_pipe[0].tag   <= s_tag;
      enc_pipe[0].dir   <= s_dir;
      enc_pipe[0].data  <= s_data ^ round_keys[0];
    end
  end

  // Stages 1 .. NR-1: full rounds
  genvar ei;
  generate
    for (ei = 1; ei < NR; ei++) begin : gen_enc
      always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) enc_pipe[ei] <= '0;
        else begin
          enc_pipe[ei].valid <= enc_pipe[ei-1].valid;
          enc_pipe[ei].tag   <= enc_pipe[ei-1].tag;
          enc_pipe[ei].dir   <= enc_pipe[ei-1].dir;
          enc_pipe[ei].data  <= enc_round(enc_pipe[ei-1].data, round_keys[ei]);
        end
      end
    end
  endgenerate

  // Final stage: no MixColumns
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) enc_pipe[NR] <= '0;
    else begin
      enc_pipe[NR].valid <= enc_pipe[NR-1].valid;
      enc_pipe[NR].tag   <= enc_pipe[NR-1].tag;
      enc_pipe[NR].dir   <= enc_pipe[NR-1].dir;
      enc_pipe[NR].data  <= enc_final_round(enc_pipe[NR-1].data,
                                                  round_keys[NR]);
    end
  end

  // ── Decryption pipeline ────────────────────────────────────────────────────
  // Round keys are used in reverse order: dec stage i uses round_keys[NR-i]
  pipe_t dec_pipe [0:NR];

  // Stage 0: Initial AddRoundKey with last round key
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) dec_pipe[0] <= '0;
    else begin
      dec_pipe[0].valid <= s_valid && (s_dir == DECRYPT);
      dec_pipe[0].tag   <= s_tag;
      dec_pipe[0].dir   <= s_dir;
      dec_pipe[0].data  <= s_data ^ round_keys[NR];
    end
  end

  // Stages 1 .. NR-1: full inverse rounds
  genvar di;
  generate
    for (di = 1; di < NR; di++) begin : gen_dec
      always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) dec_pipe[di] <= '0;
        else begin
          dec_pipe[di].valid <= dec_pipe[di-1].valid;
          dec_pipe[di].tag   <= dec_pipe[di-1].tag;
          dec_pipe[di].dir   <= dec_pipe[di-1].dir;
          dec_pipe[di].data  <= dec_round(dec_pipe[di-1].data,
                                          round_keys[NR - di]);
        end
      end
    end
  endgenerate

  // Final decryption stage: no InvMixColumns
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) dec_pipe[NR] <= '0;
    else begin
      dec_pipe[NR].valid <= dec_pipe[NR-1].valid;
      dec_pipe[NR].tag   <= dec_pipe[NR-1].tag;
      dec_pipe[NR].dir   <= dec_pipe[NR-1].dir;
      dec_pipe[NR].data  <= dec_final_round(dec_pipe[NR-1].data,
                                                  round_keys[0]);
    end
  end

  // ── Output mux — select enc or dec pipeline output ─────────────────────────
  // Both pipelines are always running; only the correct one asserts valid.
  always_comb begin
    if (enc_pipe[NR].valid) begin
      m_valid = 1'b1;
      m_data  = enc_pipe[NR].data;
      m_tag   = enc_pipe[NR].tag;
      m_dir   = enc_pipe[NR].dir;
    end else begin
      m_valid = dec_pipe[NR].valid;
      m_data  = dec_pipe[NR].data;
      m_tag   = dec_pipe[NR].tag;
      m_dir   = dec_pipe[NR].dir;
    end
  end

endmodule : aes_core
