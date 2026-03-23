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
// AES UVM Testbench — Monitor
// =============================================================================
// Passive monitor split into two logical sub-monitors in a single class:
//
//   Input sub-monitor  : captures s_valid/s_ready handshakes (block accepted)
//                        and builds a partial aes_seq_item.
//   Output sub-monitor : captures m_valid/m_data/m_err outputs, completes the
//                        item by matching tags, and writes to analysis_port_out.
//
// The input analysis port emits items as blocks are accepted; the output port
// emits items when the DUT produces a result.  The scoreboard correlates them
// via FIFO ordering (pipeline is in-order).
// =============================================================================

`ifndef AES_MONITOR_SV
`define AES_MONITOR_SV

`include "uvm_macros.svh"

class aes_monitor extends uvm_monitor;

  import aes_pkg::*;

  `uvm_component_utils(aes_monitor)

  // Analysis ports
  uvm_analysis_port #(aes_seq_item) ap_in;   // stimuli accepted by DUT
  uvm_analysis_port #(aes_seq_item) ap_out;  // results produced by DUT

  // Virtual interface (read-only via monitor_cb)
  virtual aes_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  // ---------------------------------------------------------------------------
  // build_phase
  // ---------------------------------------------------------------------------
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    ap_in  = new("ap_in",  this);
    ap_out = new("ap_out", this);

    if (!uvm_config_db #(virtual aes_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "aes_monitor: cannot get virtual interface from config_db")
  endfunction : build_phase

  // ---------------------------------------------------------------------------
  // run_phase: fork both sub-monitors
  // ---------------------------------------------------------------------------
  task run_phase(uvm_phase phase);
    fork
      monitor_input();
      monitor_output();
    join
  endtask : run_phase

  // ---------------------------------------------------------------------------
  // monitor_input: watch for s_valid & s_ready handshake
  // ---------------------------------------------------------------------------
  task monitor_input();
    aes_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.s_valid === 1'b1 && vif.monitor_cb.s_ready === 1'b1) begin
        item = aes_seq_item::type_id::create("mon_in_item");
        item.plaintext = vif.monitor_cb.s_data;
        item.mode      = vif.monitor_cb.s_mode;
        item.direction = vif.monitor_cb.s_dir;
        item.tag       = vif.monitor_cb.s_tag;
        // Key and IV are not directly observable on s_data at submission;
        // they are carried through the key_expand/iv_load transactions.
        // The scoreboard reconstructs the expected key from the sequence item.
        item.key      = '0;   // populated from key_expand observation
        item.key_bits = aes_if::KEY_BITS;
        item.iv       = '0;   // populated from iv_load observation

        `uvm_info("MON_IN",
          $sformatf("Input accepted: mode=%s dir=%s data=%h tag=%02h",
            item.mode.name(), item.direction.name(), item.plaintext, item.tag),
          UVM_HIGH)
        ap_in.write(item);
      end

      // Capture key expansion event (s_key_expand pulse)
      if (vif.monitor_cb.s_key_expand === 1'b1) begin
        `uvm_info("MON_IN",
          $sformatf("Key expansion triggered: key=%h", vif.monitor_cb.s_key_in),
          UVM_HIGH)
        // Key info is stored separately; scoreboard uses sequence item key field
      end

      // Capture IV load event
      if (vif.monitor_cb.s_iv_load === 1'b1) begin
        `uvm_info("MON_IN",
          $sformatf("IV loaded: iv=%h", vif.monitor_cb.s_iv),
          UVM_HIGH)
      end
    end
  endtask : monitor_input

  // ---------------------------------------------------------------------------
  // monitor_output: watch for m_valid assertion
  // ---------------------------------------------------------------------------
  task monitor_output();
    aes_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.m_valid === 1'b1) begin
        item = aes_seq_item::type_id::create("mon_out_item");
        item.result = vif.monitor_cb.m_data;
        item.tag    = vif.monitor_cb.m_tag;
        item.err    = vif.monitor_cb.m_err;

        `uvm_info("MON_OUT",
          $sformatf("Output valid: data=%h tag=%02h err=%0b",
            item.result, item.tag, item.err),
          UVM_HIGH)
        ap_out.write(item);
      end
    end
  endtask : monitor_output

endclass : aes_monitor

`endif // AES_MONITOR_SV
