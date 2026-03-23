#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
AES UART Hardware Test
=======================
Communicates with the AES SoC over UART (LiteX UARTBone bridge).
Tests AES-128/192/256 in ECB/CBC/CTR modes against the Python golden model.

Prerequisites:
  1. Build and load the SoC:
       python3 aes_soc.py --build --load
  2. Start the UART bridge:
       litex_server --uart --uart-port /dev/ttyUSB1 --uart-baudrate 115200
  3. Run this test:
       python3 aes_uart_test.py

CSR addresses:
  After build, check: cat build/digilent_arty/csr.csv | grep aes_
"""

import argparse
import os
import sys
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../model'))
from aes_model import AESModel

try:
    from litex.tools.litex_client import RemoteClient
    LITEX_CLIENT_AVAILABLE = True
except ImportError:
    LITEX_CLIENT_AVAILABLE = False

# Mode / direction encoding
MODE_ECB = 0
MODE_CBC = 1
MODE_CTR = 2
DIR_ENC  = 0
DIR_DEC  = 1


# ─────────────────────────────────────────────────────────────────────────────
# AESClient — high-level register interface over LiteX TCP bridge
# ─────────────────────────────────────────────────────────────────────────────

class AESClient:
    """
    High-level AES register interface via LiteX RemoteClient.

    Requires litex_server running:
        litex_server --uart --uart-port /dev/ttyUSB1 --uart-baudrate 115200
    """

    def __init__(self, host: str = "localhost", tcp_port: int = 1234,
                 csr_csv: str = None):
        self.client = RemoteClient(host=host, port=tcp_port, csr_csv=csr_csv)
        self.client.open()

    def close(self):
        self.client.close()

    # ── CSR helpers ──────────────────────────────────────────────────────────

    def _w(self, reg: str, val: int):
        getattr(self.client.regs, f"aes_{reg}").write(val & 0xFFFFFFFF)

    def _r(self, reg: str) -> int:
        return int(getattr(self.client.regs, f"aes_{reg}").read())

    # ── Key / IV / data loading ───────────────────────────────────────────────

    def load_key(self, key: bytes):
        """Write key bytes (16/24/32 bytes) to key CSR words."""
        n_words = len(key) // 4
        for i in range(n_words):
            word = int.from_bytes(key[4*i:4*i+4], 'big')
            self._w(f"key{i}", word)

    def expand_key(self):
        """Trigger key expansion and wait for key_ready."""
        self._w("ctrl", 1 << 8)  # CTRL[8] = key_expand
        for _ in range(500):
            status = self._r("status")
            if status & 0x4:  # key_ready
                return
            time.sleep(0.001)
        raise TimeoutError("key_ready never set in hardware")

    def load_iv(self, iv: bytes):
        """Write IV and trigger iv_load."""
        for i in range(4):
            word = int.from_bytes(iv[4*i:4*i+4], 'big')
            self._w(f"iv{i}", word)
        self._w("ctrl", 1 << 9)  # CTRL[9] = iv_load

    def load_din(self, data: bytes):
        """Write 16-byte plaintext/ciphertext to DIN registers."""
        for i in range(4):
            word = int.from_bytes(data[4*i:4*i+4], 'big')
            self._w(f"din{i}", word)

    def read_dout(self) -> bytes:
        """Read 16-byte result from DOUT registers."""
        out = []
        for i in range(4):
            word = self._r(f"dout{i}")
            out.extend(word.to_bytes(4, 'big'))
        return bytes(out)

    # ── Transaction ──────────────────────────────────────────────────────────

    def encrypt_decrypt(self, data: bytes, mode: int, direction: int,
                        tag: int = 0, timeout: float = 1.0) -> bytes:
        """
        Load data, trigger operation, wait for done, return result.
        mode: MODE_ECB/CBC/CTR, direction: DIR_ENC/DIR_DEC
        """
        self.load_din(data)
        self._w("tag", tag)
        ctrl = 1 | (mode << 4) | (direction << 6)  # CTRL[0]=start
        self._w("ctrl", ctrl)

        t0 = time.time()
        while True:
            status = self._r("status")
            if status & 0x1:  # done
                return self.read_dout()
            if time.time() - t0 > timeout:
                raise TimeoutError(f"AES done timeout after {timeout}s")
            time.sleep(0.001)

    # ── Info ─────────────────────────────────────────────────────────────────

    def get_version(self) -> int:
        return self._r("version")

    def get_pipe_lat(self) -> int:
        return self._r("pipe_lat")

    def get_key_size(self) -> int:
        return self._r("key_size")


# ─────────────────────────────────────────────────────────────────────────────
# AESTester
# ─────────────────────────────────────────────────────────────────────────────

class AESTester:
    def __init__(self, client: AESClient, key_bits: int = 128):
        self.client   = client
        self.key_bits = key_bits
        self.model    = AESModel(key_bits=key_bits)
        self.pass_cnt = 0
        self.fail_cnt = 0
        self.results  = []

    def check(self, label: str, dut: bytes, ref: bytes) -> bool:
        ok = (dut == ref)
        status = "PASS" if ok else "FAIL"
        msg = f"[{status}] {label}"
        if not ok:
            msg += f"\n  DUT: {dut.hex()}\n  REF: {ref.hex()}"
        print(msg)
        if ok:
            self.pass_cnt += 1
        else:
            self.fail_cnt += 1
        self.results.append((ok, label))
        return ok

    # ── Test cases ────────────────────────────────────────────────────────────

    def test_info(self):
        """Check IP version, pipeline latency, key size."""
        ver      = self.client.get_version()
        pipe_lat = self.client.get_pipe_lat()
        key_size = self.client.get_key_size()
        n_rounds = {128: 10, 192: 12, 256: 14}[self.key_bits]
        print(f"[INFO] AES IP Version    : 0x{ver:08X}")
        print(f"[INFO] Pipeline latency  : {pipe_lat} cycles (expected {n_rounds+1})")
        print(f"[INFO] Key size          : {key_size} bits")
        assert ver != 0,            "VERSION register is 0 — check connection"
        assert pipe_lat == n_rounds + 1, f"Unexpected latency {pipe_lat}"
        assert key_size == self.key_bits, f"Key size mismatch: {key_size}"
        print("[PASS] Info registers")

    def test_nist_ecb(self):
        """NIST FIPS 197 / SP 800-38A ECB vectors."""
        print(f"\n── NIST AES-{self.key_bits} ECB ──")
        vectors = {
            128: ('2b7e151628aed2a6abf7158809cf4f3c',
                  '3243f6a8885a308d313198a2e0370734',
                  '3925841d02dc09fbdc118597196a0b32'),
            192: ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
                  '6bc1bee22e409f96e93d7e117393172a',
                  'bd334f1d6e45f25ff712a214571fa5cc'),
            256: ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
                  '6bc1bee22e409f96e93d7e117393172a',
                  'f3eed1bdb5d2a03c064b5a7e3db181f8'),
        }
        key_hex, pt_hex, ct_hex = vectors[self.key_bits]
        key = bytes.fromhex(key_hex)
        pt  = bytes.fromhex(pt_hex)
        ct_exp = bytes.fromhex(ct_hex)

        self.client.load_key(key)
        self.client.expand_key()
        self.model.set_key(key)

        ct = self.client.encrypt_decrypt(pt, MODE_ECB, DIR_ENC)
        self.check(f"NIST ECB enc", ct, ct_exp)

        pt_out = self.client.encrypt_decrypt(ct_exp, MODE_ECB, DIR_DEC)
        self.check(f"NIST ECB dec", pt_out, pt)

    def test_nist_cbc(self):
        """NIST SP 800-38A F.2.1 AES-128 CBC (only for 128-bit variant)."""
        if self.key_bits != 128:
            return
        print("\n── NIST AES-128 CBC ──")
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        ct_exp = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')

        self.client.load_key(key)
        self.client.expand_key()
        self.client.load_iv(iv)

        ct = self.client.encrypt_decrypt(pt, MODE_CBC, DIR_ENC)
        self.check("NIST CBC enc", ct, ct_exp)

    def test_nist_ctr(self):
        """NIST SP 800-38A F.5.1 AES-128 CTR (only for 128-bit variant)."""
        if self.key_bits != 128:
            return
        print("\n── NIST AES-128 CTR ──")
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv  = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
        pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        ct_exp = bytes.fromhex('874d6191b620e3261bef6864990db6ce')

        self.client.load_key(key)
        self.client.expand_key()
        self.client.load_iv(iv)

        ct = self.client.encrypt_decrypt(pt, MODE_CTR, DIR_ENC)
        self.check("NIST CTR enc", ct, ct_exp)

    def test_random_ecb(self, n: int = 20):
        """Random ECB roundtrip."""
        print(f"\n── Random ECB ({n} vectors) ──")
        rng = random.Random(0xDEADAE5)
        key = bytes([rng.randint(0, 255) for _ in range(self.key_bits // 8)])
        self.client.load_key(key)
        self.client.expand_key()
        self.model.set_key(key)

        for i in range(n):
            pt  = bytes([rng.randint(0, 255) for _ in range(16)])
            ct_exp = self.model.encrypt_ecb(pt)
            ct = self.client.encrypt_decrypt(pt, MODE_ECB, DIR_ENC, tag=i)
            self.check(f"ECB enc #{i}", ct, ct_exp)

            pt_out = self.client.encrypt_decrypt(ct, MODE_ECB, DIR_DEC, tag=i)
            self.check(f"ECB dec #{i}", pt_out, pt)

    def test_random_cbc(self, n: int = 10):
        """Random CBC multi-block test."""
        print(f"\n── Random CBC ({n} blocks) ──")
        rng = random.Random(0xCBCCBC)
        key = bytes([rng.randint(0, 255) for _ in range(self.key_bits // 8)])
        iv  = bytes([rng.randint(0, 255) for _ in range(16)])

        self.client.load_key(key)
        self.client.expand_key()
        self.client.load_iv(iv)
        self.model.set_key(key)
        self.model.set_iv(iv)

        for i in range(n):
            pt  = bytes([rng.randint(0, 255) for _ in range(16)])
            ct_exp = self.model.encrypt_cbc(pt)
            ct = self.client.encrypt_decrypt(pt, MODE_CBC, DIR_ENC)
            self.check(f"CBC enc #{i}", ct, ct_exp)

    def test_random_ctr(self, n: int = 10):
        """Random CTR test."""
        print(f"\n── Random CTR ({n} blocks) ──")
        rng = random.Random(0xC7C7C7)
        key = bytes([rng.randint(0, 255) for _ in range(self.key_bits // 8)])
        iv  = bytes([rng.randint(0, 255) for _ in range(16)])

        self.client.load_key(key)
        self.client.expand_key()
        self.client.load_iv(iv)
        self.model.set_key(key)
        self.model.set_iv(iv)

        for i in range(n):
            pt  = bytes([rng.randint(0, 255) for _ in range(16)])
            ct_exp = self.model.encrypt_ctr(pt)
            ct = self.client.encrypt_decrypt(pt, MODE_CTR, DIR_ENC)
            self.check(f"CTR enc #{i}", ct, ct_exp)

    def report(self) -> bool:
        total = self.pass_cnt + self.fail_cnt
        print("\n" + "=" * 60)
        print(f"AES-{self.key_bits} Hardware Test Report")
        print(f"  TOTAL : {total}")
        print(f"  PASS  : {self.pass_cnt}")
        print(f"  FAIL  : {self.fail_cnt}")
        print("=" * 60)
        if self.fail_cnt:
            print("FAILED TESTS:")
            for ok, label in self.results:
                if not ok:
                    print(f"  {label}")
        return self.fail_cnt == 0


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AES UART Hardware Test")
    parser.add_argument("--host",       default="localhost")
    parser.add_argument("--port",       default=1234, type=int)
    parser.add_argument("--csr-csv",    default=None)
    parser.add_argument("--key-bits",   default=128, type=int, choices=[128, 192, 256])
    parser.add_argument("--random-n",   default=20, type=int)
    parser.add_argument("--skip-nist",  action="store_true")
    parser.add_argument("--skip-random", action="store_true")
    args = parser.parse_args()

    if not LITEX_CLIENT_AVAILABLE:
        print("ERROR: litex not available — activate your venv first")
        sys.exit(1)

    csr_csv = args.csr_csv
    if csr_csv is None:
        default_csv = os.path.join(os.path.dirname(__file__),
                                   "build/digilent_arty/csr.csv")
        if os.path.exists(default_csv):
            csr_csv = default_csv

    print(f"Connecting to litex_server at {args.host}:{args.port} ...")
    print("(Start server: litex_server --uart --uart-port /dev/ttyUSB1)")
    try:
        client = AESClient(host=args.host, tcp_port=args.port, csr_csv=csr_csv)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print("Connected.")
    tester = AESTester(client, key_bits=args.key_bits)

    try:
        tester.test_info()
        if not args.skip_nist:
            tester.test_nist_ecb()
            tester.test_nist_cbc()
            tester.test_nist_ctr()
        if not args.skip_random:
            tester.test_random_ecb(n=args.random_n)
            tester.test_random_cbc(n=args.random_n // 2)
            tester.test_random_ctr(n=args.random_n // 2)
    except KeyboardInterrupt:
        print("\nAborted.")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()

    ok = tester.report()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
