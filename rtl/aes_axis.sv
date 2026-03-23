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
// AES IP - AXI4-Stream Wrapper
// =============================================================================
// Provides an AXI4-Stream interface to the AES pipeline.
//
// Input stream (slave):
//   s_axis_tdata  [127:0]  plaintext (enc) or ciphertext (dec)
//   s_axis_tuser  [15:0]   {6'b0, dir[0], mode[1:0], tag[7:0]}
//   s_axis_tvalid / s_axis_tready handshake
//   s_axis_tlast  (informational, passed through to output)
//
// Output stream (master):
//   m_axis_tdata  [127:0]  ciphertext (enc) or plaintext (dec)
//   m_axis_tuser  [8:0]    {err, tag[7:0]}
//   m_axis_tvalid / m_axis_tready handshake (output FIFO provides backpressure)
//   m_axis_tlast  (passed through from input)
//
// Key / IV management sideband (not via stream):
//   s_key_in     [KEY_BITS-1:0]
//   s_key_expand  pulse → trigger key schedule
//   key_ready     1 = key expanded
//   s_iv         [127:0]
//   s_iv_load     pulse → latch IV
//
// s_axis_tuser encoding:
//   [7:0]  tag
//   [9:8]  mode: 00=ECB, 01=CBC, 10=CTR
//   [10]   dir:  0=ENCRYPT, 1=DECRYPT
//
// Output FIFO depth: FIFO_DEPTH (default 4). Prevents dropping results when
// the downstream is not ready. The pipeline stalls via s_axis_tready when
// the FIFO is full.
//
// Latency: PIPE_LAT cycles from s_axis_tvalid+tready to m_axis_tvalid
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_axis #(
  parameter int  KEY_BITS   = aes_pkg::KEY_BITS,
  parameter int  FIFO_DEPTH = 4
) (
  input  logic              clk,
  input  logic              rst_n,

  // ── Input AXI4-Stream (slave) ──────────────────────────────────────────────
  input  logic [127:0]      s_axis_tdata,
  input  logic [10:0]       s_axis_tuser,   // {dir, mode[1:0], tag[7:0]}
  input  logic              s_axis_tvalid,
  output logic              s_axis_tready,
  input  logic              s_axis_tlast,

  // ── Output AXI4-Stream (master) ───────────────────────────────────────────
  output logic [127:0]      m_axis_tdata,
  output logic [8:0]        m_axis_tuser,   // {err, tag[7:0]}
  output logic              m_axis_tvalid,
  input  logic              m_axis_tready,
  output logic              m_axis_tlast,

  // ── Key management sideband ───────────────────────────────────────────────
  input  logic [KEY_BITS-1:0] s_key_in,
  input  logic                s_key_expand,
  output logic                key_ready,

  // ── IV sideband ──────────────────────────────────────────────────────────
  input  logic [127:0]        s_iv,
  input  logic                s_iv_load
);

  // ── Decode tuser ─────────────────────────────────────────────────────────
  logic [7:0] s_tag;
  mode_t      s_mode;
  dir_t       s_dir;
  assign s_tag  = s_axis_tuser[7:0];
  assign s_mode = mode_t'(s_axis_tuser[9:8]);
  assign s_dir  = dir_t'(s_axis_tuser[10]);

  // ── AES core ──────────────────────────────────────────────────────────────
  logic         aes_s_valid, aes_s_ready;
  logic         aes_m_valid;
  logic [127:0] aes_m_data;
  logic [7:0]   aes_m_tag;
  logic         aes_m_err;

  // s_axis_tready = aes_s_ready (and FIFO not full — gated below)
  logic fifo_full;
  assign s_axis_tready = aes_s_ready && !fifo_full;
  assign aes_s_valid   = s_axis_tvalid && !fifo_full;

  aes_top #(.KEY_BITS(KEY_BITS)) u_aes (
    .clk          (clk),
    .rst_n        (rst_n),
    .s_key_in     (s_key_in),
    .s_key_expand (s_key_expand),
    .key_ready    (key_ready),
    .s_iv         (s_iv),
    .s_iv_load    (s_iv_load),
    .s_valid      (aes_s_valid && aes_s_ready),
    .s_ready      (aes_s_ready),
    .s_data       (s_axis_tdata),
    .s_mode       (s_mode),
    .s_dir        (s_dir),
    .s_tag        (s_tag),
    .m_valid      (aes_m_valid),
    .m_ready      (1'b1),
    .m_data       (aes_m_data),
    .m_tag        (aes_m_tag),
    .m_err        (aes_m_err)
  );

  // ── tlast / err pipeline (parallel to AES data pipeline) ─────────────────
  // Carry tlast and err-flag through PIPE_LAT stages alongside the data
  logic [PIPE_LAT-1:0] last_pipe;
  logic [PIPE_LAT-1:0] err_pipe;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      last_pipe <= '0;
      err_pipe  <= '0;
    end else begin
      last_pipe[0] <= s_axis_tlast && aes_s_valid && aes_s_ready;
      err_pipe[0]  <= !key_ready  && aes_s_valid && aes_s_ready;
      for (int i = 1; i < PIPE_LAT; i++) begin
        last_pipe[i] <= last_pipe[i-1];
        err_pipe[i]  <= err_pipe[i-1];
      end
    end
  end

  // ── Output FIFO (simple synchronous FIFO for backpressure) ────────────────
  localparam int FIFO_PTR_W = $clog2(FIFO_DEPTH);

  typedef struct packed {
    logic [127:0] data;
    logic [7:0]   tag;
    logic         err;
    logic         last;
  } fifo_entry_t;

  fifo_entry_t fifo_mem [0:FIFO_DEPTH-1];
  logic [FIFO_PTR_W:0] wr_ptr, rd_ptr;
  logic [FIFO_PTR_W:0] fifo_count;

  assign fifo_count = wr_ptr - rd_ptr;
  assign fifo_full  = (fifo_count == FIFO_DEPTH[FIFO_PTR_W:0]);
  logic fifo_empty;
  assign fifo_empty = (fifo_count == 0);

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      wr_ptr <= '0;
      rd_ptr <= '0;
    end else begin
      // Write when AES produces output and FIFO not full
      if (aes_m_valid && !fifo_full) begin
        fifo_mem[wr_ptr[FIFO_PTR_W-1:0]].data <= aes_m_data;
        fifo_mem[wr_ptr[FIFO_PTR_W-1:0]].tag  <= aes_m_tag;
        fifo_mem[wr_ptr[FIFO_PTR_W-1:0]].err  <= last_pipe[PIPE_LAT-1];
        fifo_mem[wr_ptr[FIFO_PTR_W-1:0]].last <= last_pipe[PIPE_LAT-1];
        wr_ptr <= wr_ptr + 1;
      end
      // Read when downstream accepts
      if (!fifo_empty && m_axis_tready) begin
        rd_ptr <= rd_ptr + 1;
      end
    end
  end

  assign m_axis_tvalid = !fifo_empty;
  assign m_axis_tdata  = fifo_mem[rd_ptr[FIFO_PTR_W-1:0]].data;
  assign m_axis_tuser  = {fifo_mem[rd_ptr[FIFO_PTR_W-1:0]].err,
                          fifo_mem[rd_ptr[FIFO_PTR_W-1:0]].tag};
  assign m_axis_tlast  = fifo_mem[rd_ptr[FIFO_PTR_W-1:0]].last;

endmodule : aes_axis
