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
// AES IP - Wishbone B4 (Classic) Wrapper
// =============================================================================
// Register map (32-bit aligned) — identical to AXI4-Lite wrapper:
//
//  0x00  CTRL      [0]=start(W/self-clear) [1]=busy(RO) [2]=done(RO)
//                  [3]=err(RO/sticky,clr-on-start) [5:4]=mode [6]=dir
//                  [8]=key_expand(W/self-clear) [9]=iv_load(W/self-clear)
//  0x04  STATUS    [0]=done [1]=busy [2]=key_ready [3]=iv_ready
//  0x08  TAG       [7:0] transaction tag
//  0x0C  VERSION   RO = IP_VERSION
//  0x10  LATENCY   RO = PIPE_LAT
//  0x14  KEY_BITS  RO = KEY_BITS (128|192|256)
//  0x20  KEY[0]    key bits [31:0]
//  0x24  KEY[1]    key bits [63:32]
//  0x28  KEY[2]    key bits [95:64]
//  0x2C  KEY[3]    key bits [127:96]
//  0x30  KEY[4]    key bits [159:128]
//  0x34  KEY[5]    key bits [191:160]
//  0x38  KEY[6]    key bits [223:192]
//  0x3C  KEY[7]    key bits [255:224]
//  0x40  IV[0]     IV bits [31:0]
//  0x44  IV[1]     IV bits [63:32]
//  0x48  IV[2]     IV bits [95:64]
//  0x4C  IV[3]     IV bits [127:96]
//  0x50  DIN[0]    data in [31:0]
//  0x54  DIN[1]    data in [63:32]
//  0x58  DIN[2]    data in [95:64]
//  0x5C  DIN[3]    data in [127:96]
//  0x60  DOUT[0]   data out [31:0]  (RO)
//  0x64  DOUT[1]   data out [63:32] (RO)
//  0x68  DOUT[2]   data out [95:64] (RO)
//  0x6C  DOUT[3]   data out [127:96](RO)
//
// Wishbone B4 Classic (non-pipelined, single-cycle ACK):
//   CYC, STB must be asserted together. ACK returned in the same cycle.
//   SEL[3:0] byte-enable (used for write masking).
//   WE=1: write, WE=0: read.
//
// irq: single-cycle pulse when done rises 0→1
// =============================================================================

`timescale 1ns/1ps

import aes_pkg::*;

module aes_wb #(
  parameter int  KEY_BITS = aes_pkg::KEY_BITS,
  parameter logic [31:0] IP_VER = aes_pkg::IP_VERSION
) (
  input  logic        clk,
  input  logic        rst_n,

  // Wishbone B4 slave (classic)
  input  logic [7:0]  wb_adr_i,
  input  logic [31:0] wb_dat_i,
  output logic [31:0] wb_dat_o,
  input  logic [3:0]  wb_sel_i,
  input  logic        wb_we_i,
  input  logic        wb_cyc_i,
  input  logic        wb_stb_i,
  output logic        wb_ack_o,
  output logic        wb_err_o,

  // Interrupt
  output logic        irq
);

  // Single-cycle ACK (registered for clean timing)
  logic wb_access;
  assign wb_access = wb_cyc_i && wb_stb_i;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) wb_ack_o <= 0;
    else        wb_ack_o <= wb_access && !wb_ack_o;
  end

  assign wb_err_o = 1'b0;

  // ── Decode ────────────────────────────────────────────────────────────────
  logic wr_valid, rd_valid;
  assign wr_valid = wb_access && wb_we_i  && !wb_ack_o;
  assign rd_valid = wb_access && !wb_we_i && !wb_ack_o;

  // ── Registers ─────────────────────────────────────────────────────────────
  logic [31:0]         reg_ctrl;
  logic [7:0]          reg_tag;
  logic [KEY_BITS-1:0] reg_key;
  logic [127:0]        reg_iv;
  logic [127:0]        reg_din;
  logic [127:0]        reg_dout;
  logic                reg_done, reg_busy, reg_err, reg_iv_ready;

  logic start_pulse, key_exp_pulse, iv_load_pulse;

  // Apply byte enables to write data
  function automatic logic [31:0] apply_sel(
    input logic [31:0] old_val,
    input logic [31:0] new_val,
    input logic [3:0]  sel
  );
    logic [31:0] result;
    for (int b = 0; b < 4; b++)
      result[8*b +: 8] = sel[b] ? new_val[8*b +: 8] : old_val[8*b +: 8];
    return result;
  endfunction

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
        logic [31:0] wdata;
        wdata = apply_sel('0, wb_dat_i, wb_sel_i);  // treat unselected as 0 for pulse bits
        unique case (wb_adr_i[7:2])
          6'h00: begin  // CTRL
            if (wb_dat_i[0] && wb_sel_i[0]) start_pulse   <= 1;
            if (wb_dat_i[8] && wb_sel_i[1]) key_exp_pulse <= 1;
            if (wb_dat_i[9] && wb_sel_i[1]) iv_load_pulse <= 1;
            if (wb_sel_i[0]) reg_ctrl[6:4] <= apply_sel(reg_ctrl, wb_dat_i, wb_sel_i)[6:4];
            if (wb_dat_i[0] && wb_sel_i[0]) reg_err <= 0;
          end
          6'h02: if (wb_sel_i[0]) reg_tag <= wb_dat_i[7:0];
          // MSB-first: KEY[0]=W[0], IV[0]=bits[127:96], DIN[0]=bits[127:96]
          6'h08: reg_key[KEY_BITS-1   -: 32] <= apply_sel(reg_key[KEY_BITS-1   -: 32], wb_dat_i, wb_sel_i);
          6'h09: reg_key[KEY_BITS-33  -: 32] <= apply_sel(reg_key[KEY_BITS-33  -: 32], wb_dat_i, wb_sel_i);
          6'h0A: reg_key[KEY_BITS-65  -: 32] <= apply_sel(reg_key[KEY_BITS-65  -: 32], wb_dat_i, wb_sel_i);
          6'h0B: reg_key[KEY_BITS-97  -: 32] <= apply_sel(reg_key[KEY_BITS-97  -: 32], wb_dat_i, wb_sel_i);
          6'h0C: if (KEY_BITS > 128) reg_key[KEY_BITS-129 -: 32] <= apply_sel(reg_key[KEY_BITS-129 -: 32], wb_dat_i, wb_sel_i);
          6'h0D: if (KEY_BITS > 128) reg_key[KEY_BITS-161 -: 32] <= apply_sel(reg_key[KEY_BITS-161 -: 32], wb_dat_i, wb_sel_i);
          /* verilator lint_off SELRANGE */
          6'h0E: if (KEY_BITS > 192) reg_key[KEY_BITS-193 -: 32] <= apply_sel(reg_key[KEY_BITS-193 -: 32], wb_dat_i, wb_sel_i);
          6'h0F: if (KEY_BITS > 192) reg_key[KEY_BITS-225 -: 32] <= apply_sel(reg_key[KEY_BITS-225 -: 32], wb_dat_i, wb_sel_i);
          /* verilator lint_on SELRANGE */
          6'h10: reg_iv[127:96]  <= apply_sel(reg_iv[127:96],  wb_dat_i, wb_sel_i);
          6'h11: reg_iv[95:64]   <= apply_sel(reg_iv[95:64],   wb_dat_i, wb_sel_i);
          6'h12: reg_iv[63:32]   <= apply_sel(reg_iv[63:32],   wb_dat_i, wb_sel_i);
          6'h13: reg_iv[31:0]    <= apply_sel(reg_iv[31:0],    wb_dat_i, wb_sel_i);
          6'h14: reg_din[127:96] <= apply_sel(reg_din[127:96], wb_dat_i, wb_sel_i);
          6'h15: reg_din[95:64]  <= apply_sel(reg_din[95:64],  wb_dat_i, wb_sel_i);
          6'h16: reg_din[63:32]  <= apply_sel(reg_din[63:32],  wb_dat_i, wb_sel_i);
          6'h17: reg_din[31:0]   <= apply_sel(reg_din[31:0],   wb_dat_i, wb_sel_i);
          default: ;
        endcase
      end

      if (iv_load_pulse) reg_iv_ready <= 1;
    end
  end

  // ── Internal signals from/to aes_top ──────────────────────────────────────
  logic         aes_key_ready;
  logic         aes_m_valid;
  logic [127:0] aes_m_data;
  logic [7:0]   aes_m_tag;
  logic         aes_m_err;
  logic         aes_s_ready;

  aes_top #(.KEY_BITS(KEY_BITS)) u_aes (
    .clk          (clk),
    .rst_n        (rst_n),
    .s_key_in     (reg_key),
    .s_key_expand (key_exp_pulse),
    .key_ready    (aes_key_ready),
    .s_iv         (reg_iv),
    .s_iv_load    (iv_load_pulse),
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
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      wb_dat_o <= '0;
    end else if (rd_valid) begin
      wb_dat_o <= '0;
      unique case (wb_adr_i[7:2])
        6'h00: wb_dat_o <= {22'h0, reg_ctrl[6:4], 1'b0,
                             aes_s_ready ? 1'b0 : 1'b1,
                             reg_err, reg_done,
                             reg_busy};
        6'h01: wb_dat_o <= {28'h0, reg_iv_ready, aes_key_ready, reg_busy, reg_done};
        6'h02: wb_dat_o <= {24'h0, reg_tag};
        6'h03: wb_dat_o <= IP_VER;
        6'h04: wb_dat_o <= PIPE_LAT;
        6'h05: wb_dat_o <= KEY_BITS;
        6'h18: wb_dat_o <= reg_dout[127:96];  // DOUT[0] = MSB
        6'h19: wb_dat_o <= reg_dout[95:64];
        6'h1A: wb_dat_o <= reg_dout[63:32];
        6'h1B: wb_dat_o <= reg_dout[31:0];
        default: wb_dat_o <= '0;
      endcase
    end
  end

endmodule : aes_wb
