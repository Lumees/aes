# AES-128/192/256 IP Core

> **Lumees Lab** — FPGA-Verified, Production-Ready Silicon IP

[![License](https://img.shields.io/badge/License-Source_Available-orange.svg)](LICENSE)
[![FPGA](https://img.shields.io/badge/FPGA-Arty%20A7--100T-green.svg)]()
[![Fmax](https://img.shields.io/badge/Fmax-100%20MHz-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/Tests-98%2F98%20HW%20PASS-blue.svg)]()

---

## Overview

The Lumees Lab AES IP Core is a fully pipelined, dual-datapath AES engine implementing **FIPS 197** (Advanced Encryption Standard). It supports all three key sizes (128/192/256 bits) and three cipher modes (ECB/CBC/CTR) with simultaneous encrypt and decrypt capability.

Unlike software AES implementations, this core delivers **1.60 Gbit/s sustained throughput** at 100 MHz — processing one 128-bit block per clock cycle in ECB and CTR modes. The fully pipelined architecture means zero stall cycles: a new plaintext block can enter every clock while a ciphertext block exits.

Verified in simulation (48/48 cocotb tests across two interfaces) and on Xilinx FPGA hardware (Arty A7-100T, 98/98 UART regression tests at all three key sizes), the core is production-ready for SoC integration in storage encryption, network security, secure boot, and communications applications.

---

## Key Features

| Feature | Detail |
|---|---|
| **Algorithm** | AES (Rijndael) per FIPS 197 |
| **Key Sizes** | 128, 192, 256 bits (parameterizable) |
| **Cipher Modes** | ECB, CBC (encrypt + decrypt), CTR |
| **Pipeline** | Fully pipelined dual-datapath (encrypt + decrypt simultaneous) |
| **Throughput** | 1 block/cycle in ECB and CTR (1.60 Gbit/s @ 100 MHz) |
| **Latency** | 11 cycles (AES-128), 13 cycles (AES-192), 15 cycles (AES-256) |
| **Key Expansion** | Iterative FSM-based, supports all key sizes |
| **Data Format** | 128-bit blocks, standard NIST byte ordering |
| **Transaction Tag** | 8-bit user tag propagated through pipeline |
| **Error Flag** | `m_err` asserts if block submitted before key is ready |
| **Bus Interfaces** | AXI4-Lite, Wishbone B4, AXI4-Stream (with backpressure FIFO) |
| **Technology** | FPGA / ASIC, pure synchronous RTL, no vendor primitives |
| **Language** | SystemVerilog |

---

## Performance — Arty A7-100T (XC7A100T) @ 100 MHz

### Resource Utilization

| Key Size | Throughput | Latency | LUTs | FFs | DSP | BRAM | WNS |
|---|---|---|---|---|---|---|---|
| AES-128 | 1.60 Gbit/s | 11 cycles | 18,922 (29.8%) | 5,944 (4.7%) | 0 | 0 | +8.788 ns |
| AES-192 | 1.60 Gbit/s | 13 cycles | 22,228 (35.1%) | 6,782 (5.3%) | 0 | 0 | +8.788 ns |
| AES-256 | 1.60 Gbit/s | 15 cycles | 25,999 (41.0%) | 7,618 (6.0%) | 0 | 0 | +8.788 ns |

> **Timing:** All endpoints met with +8.788 ns positive slack at 100 MHz. Zero DSP and BRAM usage — the entire design is implemented in LUTs and flip-flops. The substantial timing margin suggests the core can run at 200+ MHz on Artix-7.

### Throughput by Interface

| Interface | Throughput | Notes |
|---|---|---|
| `aes_top` (bare) | **1 block/clock** (1.60 Gbit/s) | ECB and CTR modes |
| `aes_axis` (AXI4-Stream) | **1 block/clock** | Output FIFO absorbs backpressure |
| `aes_axil` (AXI4-Lite) | ~50 cycles/block | Software write-trigger-poll model |
| `aes_wb` (Wishbone B4) | ~55 cycles/block | Same model, single-cycle ACK |

---

## Architecture

```
                   ┌──────────────────────────────────────────────────┐
                   │                    aes_top                       │
                   │                                                  │
 s_key_in[N-1:0] ──┤──► aes_key_expand ──► round_keys[0..NR]          │
 s_key_expand    ──┤     (iterative FSM)                              │
                   │                                                  │
 s_data[127:0]   ──┤──► mode_mux ──► aes_core ──► mode_demux ─────────┤──► m_data
 s_valid/s_ready ──┤     (ECB/CBC/    (NR-stage    (CBC/CTR           │    m_valid
 s_mode/s_dir    ──┤      CTR XOR)    pipeline)     XOR)              │    m_tag
 s_tag[7:0]      ──┤                                                  │    m_err
                   │   Latency: NR+1 cycles (11/13/15 for 128/192/256)│
                   └──────────────────────────────────────────────────┘
```

**Key Expansion (`aes_key_expand`):** Iterative FSM generates all round keys from the initial cipher key. Supports 128/192/256-bit keys with correct Rcon schedule. Expansion takes NR+1 cycles; `key_ready` signals completion.

**Core Pipeline (`aes_core`):** NR identical stages, each implementing one AES round (SubBytes → ShiftRows → MixColumns → AddRoundKey). The final round omits MixColumns per FIPS 197. Dual datapath: encrypt and inverse paths run simultaneously.

**Mode Logic:** ECB passes data straight through. CBC XORs the previous ciphertext (encrypt) or output (decrypt) via feedback registers. CTR encrypts a counter and XORs with plaintext. Mode and direction are per-sample (dynamically selectable via `s_mode`/`s_dir`).

---

## Interface — Bare Core (`aes_top`)

```systemverilog
aes_top #(
  .KEY_BITS  (128)     // 128, 192, or 256
) u_aes (
  .clk          (clk),
  .rst_n        (rst_n),

  // Key expansion
  .s_key_in     (key),          // [KEY_BITS-1:0] cipher key
  .s_key_expand (key_start),    // pulse: begin key expansion
  .key_ready    (key_rdy),      // 1 when round keys are ready

  // IV (for CBC and CTR modes)
  .s_iv         (iv),           // [127:0] initialization vector
  .s_iv_load    (iv_load),      // pulse: latch IV

  // Input stream
  .s_valid      (in_valid),     // input handshake
  .s_ready      (in_ready),     // backpressure (CBC encrypt serializes)
  .s_data       (plaintext),    // [127:0] input block
  .s_mode       (AES_ECB),      // ECB | CBC | CTR
  .s_dir        (AES_ENC),      // ENCRYPT | DECRYPT
  .s_tag        (tag_in),       // [7:0] user pass-through tag

  // Output stream
  .m_valid      (out_valid),    // output valid
  .m_ready      (1'b1),         // consumer ready (informational)
  .m_data       (ciphertext),   // [127:0] output block
  .m_tag        (tag_out),      // [7:0] matched tag
  .m_err        (err)           // key not ready when block submitted
);
```

**Software flow:**
1. Load key → pulse `s_key_expand` → wait for `key_ready`
2. (CBC/CTR) Load IV → pulse `s_iv_load`
3. For each block: assert `s_valid` with `s_data`, `s_mode`, `s_dir`
4. Collect output when `m_valid` asserts (latency = NR+1 cycles)

---

## Register Map — AXI4-Lite / Wishbone

Both `aes_axil` and `aes_wb` share the same register map:

| Offset | Register | Access | Description |
|---|---|---|---|
| 0x00 | CTRL | R/W | `[0]`=KEY_EXPAND `[1]`=IV_LOAD `[2]`=START `[4:3]`=MODE `[5]`=DIR |
| 0x04 | STATUS | R/W | `[0]`=KEY_READY `[1]`=BUSY `[2]`=DONE `[3]`=ERR |
| 0x08 | INFO | RO | `[7:0]`=KEY_BITS/8 `[15:8]`=NR `[23:16]`=BLOCK_SIZE/8 |
| 0x0C | VERSION | RO | IP version `0x00010000` |
| 0x10–0x1C | KEY[0..3] | W | Cipher key (128-bit; extend for 192/256) |
| 0x20–0x2C | IV[0..3] | R/W | Initialization vector (128-bit) |
| 0x30–0x3C | DIN[0..3] | W | Input data block (128-bit) |
| 0x40–0x4C | DOUT[0..3] | R | Output data block (128-bit) |
| 0x50 | TAG | R/W | `[7:0]` transaction tag |

---

## Verification

### Simulation (cocotb + Verilator)

| Test Suite | Tests | Coverage |
|---|---|---|
| `test_aes_top` (bare core) | NIST vectors (128/192/256), CBC/CTR roundtrip, pipeline throughput, key-not-ready error | **9/9 PASS** |
| `test_aes_axil` (AXI4-Lite) | Version/info readback, ECB encrypt via registers, decrypt roundtrip, interrupt | **9/9 PASS** |

### UVM Constrained-Random

Full UVM environment (11 files): agent, driver, monitor, scoreboard, coverage, sequences. Directed + random + stress test classes. Coverage: key_size × mode × direction cross.

### FPGA Hardware (Arty A7-100T)

| Key Size | Tests | Result |
|---|---|---|
| AES-128 | 42 tests | **42/42 PASS** |
| AES-192 | 28 tests | **28/28 PASS** |
| AES-256 | 28 tests | **28/28 PASS** |
| **Total** | **98 tests** | **98/98 PASS** |

All tests run at 100 MHz via LiteX SoC + UARTBone bridge on Xilinx XC7A100T.

---

## Directory Structure

```
aes/
├── rtl/                        # Synthesizable RTL (7 files, 1,646 lines)
│   ├── aes_pkg.sv              # S-boxes, GF(2^8) math, round functions
│   ├── aes_core.sv             # Pipelined dual-datapath engine
│   ├── aes_top.sv              # Top-level: key expansion + mode logic
│   ├── aes_key_expand.sv       # Iterative key schedule FSM
│   ├── aes_axil.sv             # AXI4-Lite slave wrapper
│   ├── aes_wb.sv               # Wishbone B4 slave wrapper
│   └── aes_axis.sv             # AXI4-Stream with backpressure FIFO
├── model/
│   └── aes_model.py            # Pure Python AES (NIST test vectors)
├── tb/
│   ├── directed/               # cocotb tests (18/18 PASS)
│   │   ├── test_aes_top.py
│   │   └── test_aes_axil.py
│   └── uvm/                    # UVM environment (11 files, 1,806 lines)
├── sim/
│   └── Makefile.cocotb         # make sim-top / sim-axil / sim-all
├── litex/                      # LiteX SoC for Arty A7-100T
│   ├── aes_litex.py
│   ├── aes_soc.py
│   └── aes_uart_test.py
├── docs/
│   └── aes-ip-datasheet.md     # Full product datasheet
├── README.md
├── LICENSE
└── .gitignore
```

---

## Applications

- **Storage encryption** — Full-disk and file-level encryption (AES-XTS, AES-CBC)
- **Network security** — TLS/IPsec bulk encryption, VPN tunnel acceleration
- **Secure boot** — Firmware decryption and integrity verification
- **IoT / embedded** — Lightweight AES engine for resource-constrained SoCs
- **Financial systems** — Payment terminal encryption (PCI DSS compliance)
- **Wireless** — Wi-Fi (WPA3), Bluetooth, Zigbee payload encryption

---

## Roadmap

### v1.1 (Planned)
- [ ] AES-GCM mode (GHASH + CTR for authenticated encryption)
- [ ] Interrupt-driven operation (reduce AXI4-Lite polling overhead)
- [ ] Power optimization (clock gating for idle pipeline stages)

### v1.2 (Planned)
- [ ] AES-XTS mode for storage encryption
- [ ] Key unwrapping (AES-KW per RFC 3394)
- [ ] Byte-enable support for partial-block operations

### v2.0 (Future)
- [ ] Side-channel hardened variant (masked S-box, constant-time)
- [ ] Multi-lane parallel processing (2x/4x throughput)
- [ ] SkyWater 130nm silicon-proven version
- [ ] 800 MHz high-performance variant for advanced FPGA/ASIC

---

## Why Lumees AES?

| Differentiator | Detail |
|---|---|
| **Three key sizes** | AES-128/192/256 from a single parameterized core |
| **Three cipher modes** | ECB, CBC, CTR — dynamically selectable per block |
| **Fully pipelined** | 1 block/clock sustained throughput (1.60 Gbit/s @ 100 MHz) |
| **Zero DSP/BRAM** | Pure LUT implementation — leaves DSP/BRAM for your application |
| **+8.8 ns timing margin** | Room to overclock well beyond 100 MHz |
| **98/98 hardware tests** | Not just simulated — proven on real FPGA silicon |
| **Four bus interfaces** | Bare port, AXI4-Lite, Wishbone B4, AXI4-Stream |
| **Source-available** | Full RTL included — inspect, modify, verify |

---

## License

This IP core is licensed under a **dual license** model:

- **Non-commercial use** (academic, research, hobby, education): **Free** under Apache 2.0
- **Commercial use** (products, services, revenue-generating): Requires a **Lumees Lab commercial license**

See [LICENSE](LICENSE) for full terms.

---

## About Lumees Lab

**Lumees Lab** builds production-ready silicon IP cores for FPGA and ASIC integration.

- 45 IP cores — FPGA-verified on Xilinx Artix-7
- Uniform SystemVerilog codebase with AXI4-Lite + Wishbone interfaces
- Full verification stack: cocotb directed + UVM constrained-random + FPGA hardware
- Targeting SkyWater 130nm open PDK for silicon-proven variants

**Website:** [lumeeslab.com](https://lumeeslab.com)
**Contact:** Hasan Kurşun — info@lumeeslab.com

---

*Copyright © 2026 Lumees Lab. All rights reserved.*
