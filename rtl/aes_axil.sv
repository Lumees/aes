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
// AES IP - AXI4-Lite Wrapper
// =============================================================================
// Register map (32-bit aligned):
//
//  0x00  CTRL      [0]=start(W/self-clear) [1]=busy(RO) [2]=done(RO)
//                  [3]=err(RO/sticky,clr-on-start) [5:4]=mode [6]=dir
//                  [8]=key_expand(W/self-clear) [9]=iv_load(W/self-clear)
//  0x04  STATUS    [0]=done [1]=busy [2]=key_ready [3]=iv_ready
//  0x08  TAG       [7:0] transaction tag
//  0x0C  VERSION   RO = IP_VERSION
//  0x10  LATENCY   RO = PIPE_LAT
//  0x14  KEY_BITS  RO = KEY_BITS (128|192|256)
//  MSB-first convention: KEY[0]/IV[0]/DIN[0] hold the MOST-significant bytes.
//  Software writes byte 0 → reg[0], which matches AES byte ordering (W[0] first).
//
//  0x20  KEY[0]    key bits [KEY_BITS-1:KEY_BITS-32]  (W[0], first key bytes)
//  0x24  KEY[1]    key bits [KEY_BITS-33:KEY_BITS-64]
//  0x28  KEY[2]    key bits [KEY_BITS-65:KEY_BITS-96]
//  0x2C  KEY[3]    key bits [KEY_BITS-97:KEY_BITS-128] ← AES-128 key complete
//  0x30  KEY[4]    (AES-192/256 only)
//  0x34  KEY[5]                                        ← AES-192 key complete
//  0x38  KEY[6]    (AES-256 only)
//  0x3C  KEY[7]                                        ← AES-256 key complete
//  0x40  IV[0]     IV bits [127:96]  (first IV bytes)
//  0x44  IV[1]     IV bits [95:64]
//  0x48  IV[2]     IV bits [63:32]
//  0x4C  IV[3]     IV bits [31:0]
//  0x50  DIN[0]    data in [127:96]  (first plaintext bytes)
//  0x54  DIN[1]    data in [95:64]
//  0x58  DIN[2]    data in [63:32]
//  0x5C  DIN[3]    data in [31:0]
//  0x60  DOUT[0]   data out [127:96] (first output bytes, RO)
//  0x64  DOUT[1]   data out [95:64]  (RO)
//  0x68  DOUT[2]   data out [63:32]  (RO)
//  0x6C  DOUT[3]   data out [31:0]   (RO)
//
// irq: single-cycle pulse when done rises 0→1
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_axil #(
  parameter int  KEY_BITS   = aes_pkg::KEY_BITS,
  parameter logic [31:0] IP_VER = aes_pkg::IP_VERSION
) (
  input  logic        clk,
  input  logic        rst_n,

  // AXI4-Lite slave
  input  logic [7:0]  s_axil_awaddr,
  input  logic        s_axil_awvalid,
  output logic        s_axil_awready,
  input  logic [31:0] s_axil_wdata,
  input  logic [3:0]  s_axil_wstrb,
  input  logic        s_axil_wvalid,
  output logic        s_axil_wready,
  output logic [1:0]  s_axil_bresp,
  output logic        s_axil_bvalid,
  input  logic        s_axil_bready,
  input  logic [7:0]  s_axil_araddr,
  input  logic        s_axil_arvalid,
  output logic        s_axil_arready,
  output logic [31:0] s_axil_rdata,
  output logic [1:0]  s_axil_rresp,
  output logic        s_axil_rvalid,
  input  logic        s_axil_rready,

  // Interrupt
  output logic        irq
);

  // ── AXI write state machine ───────────────────────────────────────────────
  logic [7:0]  wr_addr;
  logic [31:0] wr_data;
  logic        wr_valid;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      s_axil_awready <= 1; s_axil_wready <= 1;
      s_axil_bvalid  <= 0; s_axil_bresp  <= 0;
      wr_valid <= 0;
    end else begin
      wr_valid <= 0;
      if (s_axil_awvalid && s_axil_awready) begin
        wr_addr <= s_axil_awaddr;
        s_axil_awready <= 0;
      end
      if (s_axil_wvalid && s_axil_wready) begin
        wr_data <= s_axil_wdata;
        s_axil_wready <= 0;
      end
      if (!s_axil_awready && !s_axil_wready && !s_axil_bvalid) begin
        wr_valid <= 1;
        s_axil_bvalid  <= 1;
        s_axil_awready <= 1;
        s_axil_wready  <= 1;
      end
      if (s_axil_bvalid && s_axil_bready) s_axil_bvalid <= 0;
    end
  end

  // ── AXI read state machine ────────────────────────────────────────────────
  logic [7:0]  rd_addr;
  logic        rd_valid;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      s_axil_arready <= 1; s_axil_rvalid <= 0; s_axil_rresp <= 0;
      rd_valid <= 0;
    end else begin
      rd_valid <= 0;
      if (s_axil_arvalid && s_axil_arready) begin
        rd_addr        <= s_axil_araddr;
        s_axil_arready <= 0;
        rd_valid       <= 1;
      end
      if (rd_valid) s_axil_rvalid <= 1;
      if (s_axil_rvalid && s_axil_rready) begin
        s_axil_rvalid  <= 0;
        s_axil_arready <= 1;
      end
    end
  end

  // ── Registers ─────────────────────────────────────────────────────────────
  logic [31:0]         reg_ctrl;
  logic [7:0]          reg_tag;
  logic [KEY_BITS-1:0] reg_key;
  logic [127:0]        reg_iv;
  logic [127:0]        reg_din;
  logic [127:0]        reg_dout;
  logic                reg_done, reg_busy, reg_err, reg_iv_ready;

  // Pulses to aes_top
  logic start_pulse, key_exp_pulse, iv_load_pulse;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      reg_ctrl    <= '0; reg_tag  <= '0;
      reg_key     <= '0; reg_iv   <= '0; reg_din <= '0;
      reg_err     <= '0; reg_iv_ready <= '0;
      start_pulse <= 0; key_exp_pulse <= 0; iv_load_pulse <= 0;
    end else begin
      start_pulse   <= 0;
      key_exp_pulse <= 0;
      iv_load_pulse <= 0;

      if (wr_valid) begin
        unique case (wr_addr[7:2])
          6'h00: begin  // CTRL
            if (wr_data[0]) start_pulse   <= 1;
            if (wr_data[8]) key_exp_pulse <= 1;
            if (wr_data[9]) iv_load_pulse <= 1;
            reg_ctrl[6:4] <= wr_data[6:4];   // mode + dir (sticky)
            if (wr_data[0]) reg_err <= 0;    // clear err on start
          end
          6'h02: reg_tag <= wr_data[7:0];
          // KEY registers 0x20–0x3C → indices 8–15 (MSB-first: KEY[0]=W[0])
          6'h08: reg_key[KEY_BITS-1   -: 32]                   <= wr_data;
          6'h09: reg_key[KEY_BITS-33  -: 32]                   <= wr_data;
          6'h0A: reg_key[KEY_BITS-65  -: 32]                   <= wr_data;
          6'h0B: reg_key[KEY_BITS-97  -: 32]                   <= wr_data;
          6'h0C: if (KEY_BITS > 128) reg_key[KEY_BITS-129 -: 32] <= wr_data;
          6'h0D: if (KEY_BITS > 128) reg_key[KEY_BITS-161 -: 32] <= wr_data;
          /* verilator lint_off SELRANGE */
          6'h0E: if (KEY_BITS > 192) reg_key[KEY_BITS-193 -: 32] <= wr_data;
          6'h0F: if (KEY_BITS > 192) reg_key[KEY_BITS-225 -: 32] <= wr_data;
          /* verilator lint_on SELRANGE */
          // IV 0x40–0x4C → indices 16–19 (MSB-first: IV[0]=bits[127:96])
          6'h10: reg_iv[127:96] <= wr_data;
          6'h11: reg_iv[95:64]  <= wr_data;
          6'h12: reg_iv[63:32]  <= wr_data;
          6'h13: reg_iv[31:0]   <= wr_data;
          // DIN 0x50–0x5C → indices 20–23 (MSB-first: DIN[0]=bits[127:96])
          6'h14: reg_din[127:96] <= wr_data;
          6'h15: reg_din[95:64]  <= wr_data;
          6'h16: reg_din[63:32]  <= wr_data;
          6'h17: reg_din[31:0]   <= wr_data;
          default: ;
        endcase
      end

      if (iv_load_pulse) reg_iv_ready <= 1;
      if (s_iv_load_i)   reg_iv_ready <= 1;
    end
  end

  // ── Internal signals from/to aes_top ──────────────────────────────────────
  logic         aes_key_ready;
  logic         aes_m_valid;
  logic [127:0] aes_m_data;
  logic [7:0]   aes_m_tag;
  logic         aes_m_err;
  logic         aes_s_ready;
  logic         s_iv_load_i;
  assign s_iv_load_i = iv_load_pulse;

  aes_top #(.KEY_BITS(KEY_BITS)) u_aes (
    .clk          (clk),
    .rst_n        (rst_n),
    .s_key_in     (reg_key),
    .s_key_expand (key_exp_pulse),
    .key_ready    (aes_key_ready),
    .s_iv         (reg_iv),
    .s_iv_load    (s_iv_load_i),
    .s_valid      (start_pulse),
    .s_ready      (aes_s_ready),
    .s_data       (reg_din),
    .s_mode       (mode_t'(reg_ctrl[5:4])),
    .s_dir        (dir_t'(reg_ctrl[6])),
    .s_tag        (reg_tag),
    .m_valid      (aes_m_valid),
    .m_ready      (1'b1),
    .m_data       (aes_m_data),
    .m_tag        (aes_m_tag),
    .m_err        (aes_m_err)
  );

  // ── Status / done ─────────────────────────────────────────────────────────
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      reg_done <= 0; reg_busy <= 0; reg_dout <= '0;
    end else begin
      if (start_pulse)    begin reg_done <= 0; reg_busy <= 1; end
      if (aes_m_valid)    begin
        reg_done <= 1; reg_busy <= 0;
        reg_dout <= aes_m_data;
      end
      if (aes_m_err) reg_err <= 1;
    end
  end

  // irq: pulse when done rises 0→1
  logic done_prev;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin irq <= 0; done_prev <= 0; end
    else begin
      irq       <= reg_done & ~done_prev;
      done_prev <= reg_done;
    end
  end

  // ── Read mux ──────────────────────────────────────────────────────────────
  always_comb begin
    s_axil_rdata = '0;
    unique case (rd_addr[7:2])
      6'h00: s_axil_rdata = {22'h0, reg_ctrl[6:4], 1'b0,
                              aes_s_ready ? 1'b0 : 1'b1,   // busy
                              reg_err, reg_done,
                              reg_busy};
      6'h01: s_axil_rdata = {28'h0, reg_iv_ready, aes_key_ready, reg_busy, reg_done};
      6'h02: s_axil_rdata = {24'h0, reg_tag};
      6'h03: s_axil_rdata = IP_VER;
      6'h04: s_axil_rdata = PIPE_LAT;
      6'h05: s_axil_rdata = KEY_BITS;
      6'h18: s_axil_rdata = reg_dout[127:96];  // DOUT[0] = MSB
      6'h19: s_axil_rdata = reg_dout[95:64];
      6'h1A: s_axil_rdata = reg_dout[63:32];
      6'h1B: s_axil_rdata = reg_dout[31:0];
      default: s_axil_rdata = '0;
    endcase
  end

endmodule : aes_axil
