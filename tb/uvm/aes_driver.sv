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
// AES UVM Testbench — Driver
// =============================================================================
// Drives aes_top via the virtual interface clocking block.
// Protocol per DUT spec (aes_top.sv):
//   1. Write key to s_key_in, pulse s_key_expand, wait for key_ready.
//   2. If mode != ECB: write IV to s_iv, pulse s_iv_load, wait 2 clocks.
//   3. Assert s_valid with payload, wait for s_ready.
//   4. Deassert s_valid.
//   5. Wait for m_valid, capture m_data / m_err into seq_item response fields.
// =============================================================================

`ifndef AES_DRIVER_SV
`define AES_DRIVER_SV

`include "uvm_macros.svh"

class aes_driver extends uvm_driver #(aes_seq_item);

  import aes_pkg::*;

  `uvm_component_utils(aes_driver)

  // Virtual interface handle
  virtual aes_if vif;

  // Max cycles to wait for key_ready before giving up
  localparam int KEY_EXPAND_TIMEOUT = 500;
  // Max cycles to wait for s_ready / m_valid
  localparam int HANDSHAKE_TIMEOUT  = 1000;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  // ---------------------------------------------------------------------------
  // build_phase: retrieve virtual interface from config_db
  // ---------------------------------------------------------------------------
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db #(virtual aes_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "aes_driver: cannot get virtual interface from config_db")
  endfunction : build_phase

  // ---------------------------------------------------------------------------
  // run_phase: main driver loop
  // ---------------------------------------------------------------------------
  task run_phase(uvm_phase phase);
    aes_seq_item req, rsp;

    // Initialise all driven signals to safe defaults
    vif.driver_cb.s_key_in     <= '0;
    vif.driver_cb.s_key_expand <= 1'b0;
    vif.driver_cb.s_iv         <= '0;
    vif.driver_cb.s_iv_load    <= 1'b0;
    vif.driver_cb.s_valid      <= 1'b0;
    vif.driver_cb.s_data       <= '0;
    vif.driver_cb.s_mode       <= ECB;
    vif.driver_cb.s_dir        <= ENCRYPT;
    vif.driver_cb.s_tag        <= 8'h00;
    vif.driver_cb.m_ready      <= 1'b1;  // always ready to accept output

    // Wait for reset to deassert
    @(posedge vif.clk);
    wait (vif.rst_n === 1'b1);
    @(posedge vif.clk);

    forever begin
      // Get next item from sequencer
      seq_item_port.get_next_item(req);
      `uvm_info("DRV", $sformatf("Driving: %s", req.convert2string()), UVM_HIGH)

      // Clone for response
      rsp = aes_seq_item::type_id::create("rsp");
      rsp.copy(req);

      // ------------------------------------------------------------------
      // Step 1: Key expansion
      // ------------------------------------------------------------------
      drive_key_expand(req);

      // ------------------------------------------------------------------
      // Step 2: IV load (CBC / CTR only)
      // ------------------------------------------------------------------
      if (req.mode != ECB) begin
        drive_iv_load(req);
      end

      // ------------------------------------------------------------------
      // Step 3–4: Submit block and wait for s_ready handshake
      // ------------------------------------------------------------------
      drive_block(req);

      // ------------------------------------------------------------------
      // Step 5: Capture output
      // ------------------------------------------------------------------
      capture_output(rsp);

      // Return response to sequence
      seq_item_port.item_done(rsp);
    end
  endtask : run_phase

  // ---------------------------------------------------------------------------
  // drive_key_expand: load key, pulse s_key_expand, wait for key_ready
  // ---------------------------------------------------------------------------
  task drive_key_expand(aes_seq_item item);
    int timeout;

    // Present key
    @(vif.driver_cb);
    vif.driver_cb.s_key_in     <= item.key[aes_if::KEY_BITS-1:0];
    vif.driver_cb.s_key_expand <= 1'b1;
    @(vif.driver_cb);
    vif.driver_cb.s_key_expand <= 1'b0;

    // Wait for key_ready
    timeout = 0;
    while (!vif.driver_cb.key_ready) begin
      @(vif.driver_cb);
      timeout++;
      if (timeout >= KEY_EXPAND_TIMEOUT)
        `uvm_fatal("DRV_TIMEOUT",
          $sformatf("key_ready never asserted after %0d cycles", KEY_EXPAND_TIMEOUT))
    end
    `uvm_info("DRV", "key_ready asserted", UVM_HIGH)
  endtask : drive_key_expand

  // ---------------------------------------------------------------------------
  // drive_iv_load: present IV, pulse s_iv_load, wait 2 clocks for settling
  // ---------------------------------------------------------------------------
  task drive_iv_load(aes_seq_item item);
    @(vif.driver_cb);
    vif.driver_cb.s_iv      <= item.iv;
    vif.driver_cb.s_iv_load <= 1'b1;
    @(vif.driver_cb);
    vif.driver_cb.s_iv_load <= 1'b0;
    // Allow IV to settle into the DUT registers
    @(vif.driver_cb);
    @(vif.driver_cb);
    `uvm_info("DRV", $sformatf("IV loaded: %h", item.iv), UVM_HIGH)
  endtask : drive_iv_load

  // ---------------------------------------------------------------------------
  // drive_block: assert s_valid, wait for s_ready, then deassert
  // ---------------------------------------------------------------------------
  task drive_block(aes_seq_item item);
    int timeout;

    @(vif.driver_cb);
    vif.driver_cb.s_valid <= 1'b1;
    vif.driver_cb.s_data  <= item.plaintext;
    vif.driver_cb.s_mode  <= item.mode;
    vif.driver_cb.s_dir   <= item.direction;
    vif.driver_cb.s_tag   <= item.tag;

    // Wait for handshake (s_valid & s_ready)
    timeout = 0;
    while (!vif.driver_cb.s_ready) begin
      @(vif.driver_cb);
      timeout++;
      if (timeout >= HANDSHAKE_TIMEOUT)
        `uvm_fatal("DRV_TIMEOUT",
          $sformatf("s_ready never asserted after %0d cycles", HANDSHAKE_TIMEOUT))
    end
    // One clock of accepted transfer
    @(vif.driver_cb);
    vif.driver_cb.s_valid <= 1'b0;
    `uvm_info("DRV", "Block accepted (s_valid & s_ready)", UVM_HIGH)
  endtask : drive_block

  // ---------------------------------------------------------------------------
  // capture_output: wait for m_valid, read m_data / m_err
  // ---------------------------------------------------------------------------
  task capture_output(aes_seq_item rsp);
    int timeout;

    timeout = 0;
    @(vif.driver_cb);
    while (!vif.driver_cb.m_valid) begin
      @(vif.driver_cb);
      timeout++;
      if (timeout >= HANDSHAKE_TIMEOUT)
        `uvm_fatal("DRV_TIMEOUT",
          $sformatf("m_valid never asserted after %0d cycles", HANDSHAKE_TIMEOUT))
    end

    rsp.result = vif.driver_cb.m_data;
    rsp.err    = vif.driver_cb.m_err;
    `uvm_info("DRV",
      $sformatf("Output captured: result=%h err=%0b", rsp.result, rsp.err),
      UVM_HIGH)
  endtask : capture_output

endclass : aes_driver

`endif // AES_DRIVER_SV
