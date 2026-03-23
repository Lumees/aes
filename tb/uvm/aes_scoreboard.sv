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
// AES UVM Testbench — Scoreboard
// =============================================================================
// Self-checking scoreboard:
//   - Receives stimulus items from the input monitor (ap_in)
//   - Receives response items from the output monitor (ap_out)
//   - For ECB mode: computes expected result using aes_pkg primitives
//   - Compares DUT output with reference model
//   - Reports pass/fail counts in check_phase
//
// CBC / CTR reference checking is deferred to cocotb (python) directed tests.
// The scoreboard flags CBC/CTR results as "INFO-only" and counts them separately.
//
// Reference model key schedule:
//   Implements FIPS-197 key expansion in SV using aes_pkg::rcon/sbox_fwd.
//   Supports AES-128, AES-192, AES-256.
// =============================================================================

`ifndef AES_SCOREBOARD_SV
`define AES_SCOREBOARD_SV

`include "uvm_macros.svh"

class aes_scoreboard extends uvm_scoreboard;

  import aes_pkg::*;

  `uvm_component_utils(aes_scoreboard)

  // TLM FIFOs fed from the monitor analysis ports
  uvm_tlm_analysis_fifo #(aes_seq_item) fifo_in;
  uvm_tlm_analysis_fifo #(aes_seq_item) fifo_out;

  // Analysis exports (connected to monitor analysis ports in env)
  uvm_analysis_export #(aes_seq_item) ae_in;
  uvm_analysis_export #(aes_seq_item) ae_out;

  // Counters
  int unsigned pass_count;
  int unsigned fail_count;
  int unsigned skip_count;   // CBC/CTR — not checked here

  // ── Reference model storage ────────────────────────────────────────────────
  // The scoreboard must know the key for each transaction.  Since the monitor
  // cannot observe the key on the data bus at block-submission time, we rely on
  // the sequence passing through the key via a "pending queue" populated by
  // the agent's analysis port carrying the full seq_item (including key field).
  // The seq_item written to ap_in by the driver/monitor has key='0, so the
  // scoreboard also exposes a separate write port for full-item context.
  uvm_analysis_export #(aes_seq_item) ae_context;  // full seq_item from sequences
  uvm_tlm_analysis_fifo #(aes_seq_item) fifo_context;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    pass_count  = 0;
    fail_count  = 0;
    skip_count  = 0;
  endfunction : new

  // ---------------------------------------------------------------------------
  // build_phase
  // ---------------------------------------------------------------------------
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    fifo_in      = new("fifo_in",      this);
    fifo_out     = new("fifo_out",     this);
    fifo_context = new("fifo_context", this);
    ae_in        = new("ae_in",        this);
    ae_out       = new("ae_out",       this);
    ae_context   = new("ae_context",   this);
  endfunction : build_phase

  // ---------------------------------------------------------------------------
  // connect_phase: wire exports to FIFOs
  // ---------------------------------------------------------------------------
  function void connect_phase(uvm_phase phase);
    ae_in.connect      (fifo_in.analysis_export);
    ae_out.connect     (fifo_out.analysis_export);
    ae_context.connect (fifo_context.analysis_export);
  endfunction : connect_phase

  // ---------------------------------------------------------------------------
  // run_phase: drain FIFOs and check
  // ---------------------------------------------------------------------------
  task run_phase(uvm_phase phase);
    aes_seq_item stim_item, resp_item, ctx_item;
    logic [127:0] expected;
    string        mode_str;

    forever begin
      // Wait for a DUT output
      fifo_out.get(resp_item);

      // Get matching stimulus (in-order pipeline)
      fifo_in.get(stim_item);

      // Get full context with key (sent by the sequence/driver path)
      fifo_context.get(ctx_item);

      mode_str = ctx_item.mode.name();

      if (resp_item.err) begin
        `uvm_error("SB_ERR",
          $sformatf("DUT reported m_err=1 for transaction: %s", ctx_item.convert2string()))
        fail_count++;
        continue;
      end

      case (ctx_item.mode)
        ECB: begin
          // Compute reference ECB result
          if (ctx_item.direction == ENCRYPT)
            expected = ref_aes_ecb_encrypt(ctx_item.plaintext,
                                           ctx_item.key,
                                           ctx_item.key_bits);
          else
            expected = ref_aes_ecb_decrypt(ctx_item.plaintext,
                                           ctx_item.key,
                                           ctx_item.key_bits);

          if (resp_item.result === expected) begin
            pass_count++;
            `uvm_info("SB_PASS",
              $sformatf("PASS ECB %s | pt=%h | key[127:0]=%h | exp=%h | got=%h",
                ctx_item.direction.name(),
                ctx_item.plaintext,
                ctx_item.key[127:0],
                expected,
                resp_item.result),
              UVM_MEDIUM)
          end else begin
            fail_count++;
            `uvm_error("SB_FAIL",
              $sformatf("FAIL ECB %s | pt=%h | key[127:0]=%h | exp=%h | got=%h",
                ctx_item.direction.name(),
                ctx_item.plaintext,
                ctx_item.key[127:0],
                expected,
                resp_item.result))
          end
        end

        CBC, CTR: begin
          // NOTE: CBC/CTR reference checking is performed by the cocotb directed
          // test suite (tb/directed/test_aes_top.py).  The UVM scoreboard logs
          // the transaction but does not assert pass/fail for these modes.
          skip_count++;
          `uvm_info("SB_SKIP",
            $sformatf("SKIP %s %s (reference check delegated to cocotb) | pt=%h | result=%h",
              mode_str,
              ctx_item.direction.name(),
              ctx_item.plaintext,
              resp_item.result),
            UVM_MEDIUM)
        end

        default: begin
          `uvm_warning("SB_UNDEF", $sformatf("Unknown mode %0d — skipping", ctx_item.mode))
          skip_count++;
        end
      endcase
    end
  endtask : run_phase

  // ---------------------------------------------------------------------------
  // check_phase: summary report
  // ---------------------------------------------------------------------------
  function void check_phase(uvm_phase phase);
    super.check_phase(phase);
    `uvm_info("SB_SUMMARY",
      $sformatf("Scoreboard results: PASS=%0d  FAIL=%0d  SKIP(CBC/CTR)=%0d",
        pass_count, fail_count, skip_count),
      UVM_NONE)

    if (fail_count > 0)
      `uvm_error("SB_SUMMARY",
        $sformatf("%0d transaction(s) FAILED — see above for details", fail_count))

    if (!fifo_in.is_empty())
      `uvm_warning("SB_LEFTOVERS",
        $sformatf("%0d input item(s) unmatched in fifo_in at end of test",
          fifo_in.used()))

    if (!fifo_out.is_empty())
      `uvm_warning("SB_LEFTOVERS",
        $sformatf("%0d output item(s) unmatched in fifo_out at end of test",
          fifo_out.used()))
  endfunction : check_phase

  // ===========================================================================
  // Reference Model — AES Key Schedule (FIPS 197 §5.2)
  // ===========================================================================

  // ── sub_word helper ─────────────────────────────────────────────────────────
  function automatic logic [31:0] ref_sub_word(input logic [31:0] w);
    return { sbox_fwd(w[31:24]),
             sbox_fwd(w[23:16]),
             sbox_fwd(w[15: 8]),
             sbox_fwd(w[ 7: 0]) };
  endfunction : ref_sub_word

  // ── rot_word helper ─────────────────────────────────────────────────────────
  function automatic logic [31:0] ref_rot_word(input logic [31:0] w);
    return { w[23:0], w[31:24] };
  endfunction : ref_rot_word

  // ── Key expansion ───────────────────────────────────────────────────────────
  // Returns an array of N_ROUND_KEYS 128-bit round keys.
  // key_in is right-justified (key[key_bits-1:0] is used).
  //
  // FIPS 197 uses 32-bit words; we store them as 128-bit (4 words per key).
  function automatic void ref_key_expand(
    input  logic [255:0]    key_in,
    input  int unsigned     key_bits,
    output logic [127:0]    rk [0:14]  // max 15 round keys (AES-256)
  );
    int nk;               // number of 32-bit key words
    int nr;               // number of rounds
    int total_words;      // total words in expanded key schedule
    logic [31:0] w [];   // expanded word array

    nk = key_bits / 32;
    nr = (key_bits == 128) ? 10 : (key_bits == 192) ? 12 : 14;
    total_words = 4 * (nr + 1);

    w = new [total_words];

    // Load initial key words (big-endian: MSB of key → w[0])
    for (int i = 0; i < nk; i++) begin
      // key_in[255:0]; word 0 = bits[255:224] for 256, [127:96] for 128
      // For key_bits=128: key_in[127:0] has the key.
      // word i = key_in[key_bits-1 - 32*i -: 32]
      w[i] = key_in[key_bits - 1 - 32*i -: 32];
    end

    for (int i = nk; i < total_words; i++) begin
      logic [31:0] tmp;
      tmp = w[i-1];
      if (i % nk == 0)
        tmp = ref_sub_word(ref_rot_word(tmp)) ^ {rcon(i/nk), 24'h0};
      else if (nk > 6 && (i % nk == 4))
        tmp = ref_sub_word(tmp);
      w[i] = w[i - nk] ^ tmp;
    end

    // Pack words into 128-bit round keys
    for (int r = 0; r <= nr; r++) begin
      rk[r] = { w[4*r], w[4*r+1], w[4*r+2], w[4*r+3] };
    end
  endfunction : ref_key_expand

  // ── ECB Encrypt ─────────────────────────────────────────────────────────────
  function automatic logic [127:0] ref_aes_ecb_encrypt(
    input logic [127:0] pt,
    input logic [255:0] key,
    input int unsigned  key_bits
  );
    logic [127:0] rk [0:14];
    logic [127:0] state;
    int           nr;

    ref_key_expand(key, key_bits, rk);
    nr    = (key_bits == 128) ? 10 : (key_bits == 192) ? 12 : 14;
    state = pt ^ rk[0];

    for (int r = 1; r < nr; r++)
      state = enc_round(state, rk[r]);

    state = enc_final_round(state, rk[nr]);
    return state;
  endfunction : ref_aes_ecb_encrypt

  // ── ECB Decrypt ─────────────────────────────────────────────────────────────
  function automatic logic [127:0] ref_aes_ecb_decrypt(
    input logic [127:0] ct,
    input logic [255:0] key,
    input int unsigned  key_bits
  );
    logic [127:0] rk [0:14];
    logic [127:0] state;
    int           nr;

    ref_key_expand(key, key_bits, rk);
    nr    = (key_bits == 128) ? 10 : (key_bits == 192) ? 12 : 14;
    state = ct ^ rk[nr];

    for (int r = nr-1; r > 0; r--)
      state = dec_round(state, rk[r]);

    state = dec_final_round(state, rk[0]);
    return state;
  endfunction : ref_aes_ecb_decrypt

endclass : aes_scoreboard

`endif // AES_SCOREBOARD_SV
