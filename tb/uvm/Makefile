# =============================================================================
# Copyright (c) 2026 Lumees Lab
# SPDX-License-Identifier: MIT
# =============================================================================
# AES UVM Testbench — Makefile
# Supports: Questa / ModelSim (default), VCS (SIM=vcs)
# =============================================================================
#
# Usage:
#   make sim              # compile + run with default test (aes_nist_test)
#   make sim-nist         # NIST vector test
#   make sim-random       # 50 random mixed-mode transactions
#   make sim-stress       # 200 random mixed-mode transactions
#   make compile          # compile only
#   make run              # run only (must compile first)
#   make clean            # remove build artefacts
#
# Overrides:
#   make sim KEY_BITS=256 UVM_TEST=aes_random_test
#   make sim SIM=vcs
# =============================================================================

# ── Simulator selection ────────────────────────────────────────────────────────
SIM       ?= questa

# ── Design under test ─────────────────────────────────────────────────────────
TOP        = aes_tb_top
RTL_DIR    = ../../rtl
UVM_HOME  ?= $(QUESTA_HOME)/verilog_src/uvm-1.2

# ── Test / DUT parameters ────────────────────────────────────────────────────
KEY_BITS  ?= 128
UVM_TEST  ?= aes_nist_test
UVM_VERB  ?= UVM_MEDIUM
SEED      ?= 1

# ── Build directories ────────────────────────────────────────────────────────
BUILD_DIR  = work
LOG_DIR    = logs

# ── RTL source list ──────────────────────────────────────────────────────────
RTL_SRCS = \
	$(RTL_DIR)/aes_pkg.sv          \
	$(RTL_DIR)/aes_key_expand.sv   \
	$(RTL_DIR)/aes_core.sv         \
	$(RTL_DIR)/aes_top.sv

# ── TB source (top includes all others via `include) ─────────────────────────
TB_TOP = aes_tb_top.sv

# =============================================================================
# Questa / ModelSim targets
# =============================================================================
ifeq ($(SIM),questa)

VLOG  = vlog
VSIM  = vsim

VLOG_FLAGS  = -sv \
              +incdir+$(RTL_DIR) \
              +incdir+. \
              +define+AES_KEY_BITS=$(KEY_BITS) \
              +define+KEY_BITS=$(KEY_BITS) \
              -timescale "1ns/1ps" \
              -work $(BUILD_DIR)

VSIM_FLAGS  = -sv_seed $(SEED) \
              -t 1ns \
              +UVM_TESTNAME=$(UVM_TEST) \
              +UVM_VERBOSITY=$(UVM_VERB) \
              +KEY_BITS=$(KEY_BITS) \
              -permit_unmatched_virtual_intf \
              -do "run -all; quit -f"

.PHONY: compile
compile: $(BUILD_DIR)/_lib.qdb

$(BUILD_DIR)/_lib.qdb: $(RTL_SRCS) $(TB_TOP)
	@mkdir -p $(BUILD_DIR) $(LOG_DIR)
	$(VLOG) -work $(BUILD_DIR) $(VLOG_FLAGS) $(RTL_SRCS) $(TB_TOP) \
		2>&1 | tee $(LOG_DIR)/compile.log
	@echo "Compilation complete."

.PHONY: run
run:
	@mkdir -p $(LOG_DIR)
	$(VSIM) $(VSIM_FLAGS) \
		-work $(BUILD_DIR) \
		$(TOP) \
		2>&1 | tee $(LOG_DIR)/run_$(UVM_TEST)_k$(KEY_BITS).log

.PHONY: sim
sim: compile run

# Named convenience targets
.PHONY: sim-nist
sim-nist:
	$(MAKE) sim UVM_TEST=aes_nist_test

.PHONY: sim-random
sim-random:
	$(MAKE) sim UVM_TEST=aes_random_test

.PHONY: sim-stress
sim-stress:
	$(MAKE) sim UVM_TEST=aes_stress_test UVM_VERB=UVM_MEDIUM

# Run all three in sequence
.PHONY: sim-all
sim-all: sim-nist sim-random sim-stress

endif  # questa

# =============================================================================
# VCS targets
# =============================================================================
ifeq ($(SIM),vcs)

VCS      = vcs
SIMV_OUT = simv

VCS_FLAGS = -sverilog \
            +incdir+$(RTL_DIR) \
            +incdir+. \
            +define+AES_KEY_BITS=$(KEY_BITS) \
            +define+KEY_BITS=$(KEY_BITS) \
            -timescale=1ns/1ps \
            -ntb_opts uvm \
            -full64 \
            -debug_access+all

SIMV_FLAGS = +UVM_TESTNAME=$(UVM_TEST) \
             +UVM_VERBOSITY=$(UVM_VERB) \
             +KEY_BITS=$(KEY_BITS) \
             -sv_seed $(SEED)

.PHONY: compile
compile:
	@mkdir -p $(LOG_DIR)
	$(VCS) $(VCS_FLAGS) $(RTL_SRCS) $(TB_TOP) \
		-o $(SIMV_OUT) \
		2>&1 | tee $(LOG_DIR)/compile.log

.PHONY: run
run:
	@mkdir -p $(LOG_DIR)
	./$(SIMV_OUT) $(SIMV_FLAGS) \
		2>&1 | tee $(LOG_DIR)/run_$(UVM_TEST)_k$(KEY_BITS).log

.PHONY: sim
sim: compile run

.PHONY: sim-nist
sim-nist:
	$(MAKE) sim UVM_TEST=aes_nist_test

.PHONY: sim-random
sim-random:
	$(MAKE) sim UVM_TEST=aes_random_test

.PHONY: sim-stress
sim-stress:
	$(MAKE) sim UVM_TEST=aes_stress_test UVM_VERB=UVM_MEDIUM

.PHONY: sim-all
sim-all: sim-nist sim-random sim-stress

endif  # vcs

# =============================================================================
# Clean
# =============================================================================
.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR) $(LOG_DIR) $(SIMV_OUT) simv.daidir \
	        transcript vsim.wlf *.log *.vcd *.fsdb ucdb \
	        csrc DVEfiles inter.vpd urgReport
	@echo "Clean complete."

# =============================================================================
# Help
# =============================================================================
.PHONY: help
help:
	@echo ""
	@echo "AES UVM Testbench Makefile"
	@echo "──────────────────────────"
	@echo "Targets:"
	@echo "  sim           Compile + run (default test: $(UVM_TEST))"
	@echo "  sim-nist      Run NIST vector test"
	@echo "  sim-random    Run 50 random mixed-mode transactions"
	@echo "  sim-stress    Run 200 random stress transactions"
	@echo "  sim-all       Run nist + random + stress"
	@echo "  compile       Compile only"
	@echo "  run           Run only (compile first)"
	@echo "  clean         Remove all build artefacts"
	@echo ""
	@echo "Key variables:"
	@echo "  SIM       Simulator: questa (default) | vcs"
	@echo "  KEY_BITS  AES key width: 128 (default) | 192 | 256"
	@echo "  UVM_TEST  Test class name (default: aes_nist_test)"
	@echo "  UVM_VERB  UVM verbosity (default: UVM_MEDIUM)"
	@echo "  SEED      Random seed (default: 1)"
	@echo ""
	@echo "Examples:"
	@echo "  make sim KEY_BITS=256 UVM_TEST=aes_random_test SEED=42"
	@echo "  make sim-stress SIM=vcs KEY_BITS=192"
	@echo ""
