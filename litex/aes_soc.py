#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
AES SoC for Arty A7-100T
==========================
Builds a LiteX SoC with:
  - No CPU (UARTBone for register access)
  - UART (115200 baud)
  - AES IP (AES-128/192/256, ECB/CBC/CTR)
  - LED control CSR

Usage:
    cd litex/
    python3 aes_soc.py --build                    # synthesize + implement
    python3 aes_soc.py --key-bits 256 --build      # AES-256 variant
    python3 aes_soc.py --load                      # program Arty via USB

Then test:
    litex_server --uart --uart-port /dev/ttyUSB1
    python3 aes_uart_test.py
"""

import argparse
import os
import sys

from migen import *

from litex.soc.cores.clock            import S7PLL
from litex.soc.integration.soc_core   import SoCCore, soc_core_argdict, soc_core_args
from litex.soc.integration.builder    import Builder, builder_argdict, builder_args
from litex.soc.interconnect.csr       import *
from litex.soc.cores.gpio             import GPIOOut

from litex_boards.platforms import digilent_arty

sys.path.insert(0, os.path.dirname(__file__))
from aes_litex import AES


# ─────────────────────────────────────────────
# CRG
# ─────────────────────────────────────────────
class _CRG(Module):
    def __init__(self, platform, sys_clk_freq):
        self.rst = Signal()
        self.clock_domains.cd_sys = ClockDomain()

        self.submodules.pll = pll = S7PLL(speedgrade=-1)
        self.comb += pll.reset.eq(~platform.request("cpu_reset") | self.rst)
        pll.register_clkin(platform.request("clk100"), 100e6)
        pll.create_clkout(self.cd_sys, sys_clk_freq)

        platform.add_false_path_constraints(self.cd_sys.clk)


# ─────────────────────────────────────────────
# AES SoC
# ─────────────────────────────────────────────
class AESSoC(SoCCore):
    def __init__(self, sys_clk_freq: float = 100e6, key_bits: int = 128, **kwargs):
        platform = digilent_arty.Platform(variant="a7-100")

        kwargs["cpu_type"]             = None
        kwargs["uart_name"]            = "uartbone"
        kwargs["integrated_rom_size"]  = 0
        kwargs["integrated_sram_size"] = 0
        SoCCore.__init__(self, platform,
            clk_freq = sys_clk_freq,
            ident    = f"AES-{key_bits} IP Test SoC - Arty A7-100T",
            **kwargs
        )

        self.submodules.crg = _CRG(platform, sys_clk_freq)

        # AES IP
        self.submodules.aes = AES(platform, key_bits=key_bits,
                                  sys_clk_freq=sys_clk_freq)
        self.add_csr("aes")

        # LEDs
        leds = platform.request_all("user_led")
        self.submodules.leds = GPIOOut(leds)
        self.add_csr("leds")

        platform.add_platform_command(
            "set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]")
        platform.add_platform_command(
            "set_property CONFIG_VOLTAGE 3.3 [current_design]")
        platform.add_platform_command(
            "set_property CFGBVS VCCO [current_design]")


# ─────────────────────────────────────────────
# Build / Load
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AES SoC for Arty A7-100T")
    parser.add_argument("--build",        action="store_true", help="Build design")
    parser.add_argument("--load",         action="store_true", help="Load bitstream via JTAG")
    parser.add_argument("--sys-clk-freq", default=100e6, type=float)
    parser.add_argument("--key-bits",     default=128, type=int, choices=[128, 192, 256])
    builder_args(parser)
    soc_core_args(parser)
    args = parser.parse_args()

    soc = AESSoC(
        sys_clk_freq = int(args.sys_clk_freq),
        key_bits     = args.key_bits,
        **soc_core_argdict(args)
    )

    builder = Builder(soc, **builder_argdict(args))
    builder.build(run=args.build)

    if args.load:
        prog = soc.platform.create_programmer()
        prog.load_bitstream(
            os.path.join(builder.gateware_dir, soc.build_name + ".bit")
        )


if __name__ == "__main__":
    main()
