# =============================================================================
# AES IP - Master Makefile
# =============================================================================
# Targets:
#   make sim           - cocotb/Verilator simulation (aes_top + aes_axil)
#   make sim-top       - simulate aes_top only
#   make sim-axil      - simulate aes_axil only
#   make sim-128       - AES-128 (default)
#   make sim-192       - AES-192
#   make sim-256       - AES-256
#   make sim-all-keys  - run all key sizes
#   make model         - run Python golden model self-test
#   make lint          - run Verilator lint
#   make build         - build LiteX SoC (requires Vivado)
#   make load          - load bitstream to Arty A7
#   make hw-test       - run UART hardware test
#   make clean         - clean build artifacts
# =============================================================================

SHELL   := /bin/bash
TOP_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Override VENV on the command line:  make sim VENV=/path/to/venv
# Shared venv lives one level up from the project root
VENV  ?= $(TOP_DIR)/../.venv
PY    := $(VENV)/bin/python3
PIP   := $(VENV)/bin/pip

RTL_DIR   := $(TOP_DIR)/rtl
TB_DIR    := $(TOP_DIR)/tb
MODEL_DIR := $(TOP_DIR)/model
LITEX_DIR := $(TOP_DIR)/litex
SIM_DIR   := $(TOP_DIR)/sim
BUILD_DIR := $(TOP_DIR)/build

UART_PORT ?= /dev/ttyUSB1
KEY_BITS  ?= 128

# RTL sources (order matters: package first)
RTL_SRCS := \
    $(RTL_DIR)/aes_pkg.sv        \
    $(RTL_DIR)/aes_key_expand.sv \
    $(RTL_DIR)/aes_core.sv       \
    $(RTL_DIR)/aes_top.sv        \
    $(RTL_DIR)/aes_axil.sv       \
    $(RTL_DIR)/aes_wb.sv         \
    $(RTL_DIR)/aes_axis.sv

# ─────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "AES IP Makefile"
	@echo "==============="
	@echo "  make sim           Run cocotb/Verilator simulation (top + axil)"
	@echo "  make sim-top       Simulate aes_top"
	@echo "  make sim-axil      Simulate aes_axil (AXI4-Lite)"
	@echo "  make sim-128       AES-128 sim"
	@echo "  make sim-192       AES-192 sim"
	@echo "  make sim-256       AES-256 sim"
	@echo "  make sim-all-keys  Run all key sizes"
	@echo "  make model         Python golden model self-test"
	@echo "  make lint          Verilator lint check"
	@echo "  make build         Build LiteX SoC (requires Vivado)"
	@echo "  make load          Load bitstream to Arty A7"
	@echo "  make hw-test       UART hardware test"
	@echo "  make clean         Clean build artifacts"
	@echo ""

# ─────────────────────────────────────────────
# Python golden model
# ─────────────────────────────────────────────
.PHONY: model
model:
	@echo "=== AES golden model self-test ==="
	$(PY) $(MODEL_DIR)/aes_model.py

# ─────────────────────────────────────────────
# Verilator lint
# ─────────────────────────────────────────────
.PHONY: lint
lint: $(BUILD_DIR)
	@echo "=== Running Verilator lint (AES-$(KEY_BITS)) ==="
	verilator --lint-only --sv --top aes_top \
	    -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-UNUSED -Wno-CASEINCOMPLETE \
	    $(RTL_DIR)/aes_pkg.sv        \
	    $(RTL_DIR)/aes_key_expand.sv \
	    $(RTL_DIR)/aes_core.sv       \
	    $(RTL_DIR)/aes_top.sv        \
	    2>&1 | tee $(BUILD_DIR)/lint.log
	@echo "Lint complete. Log: build/lint.log"

# ─────────────────────────────────────────────
# cocotb / Verilator simulation
# ─────────────────────────────────────────────
.PHONY: sim sim-top sim-axil
sim: sim-top sim-axil

sim-top: $(BUILD_DIR)
	@echo "=== aes_top cocotb sim (AES-$(KEY_BITS)) ==="
	cd $(SIM_DIR) && \
	    PATH="$(VENV)/bin:$$PATH" \
	    PYTHON_BIN="$(VENV)/bin/python3" \
	    PYTHONPATH=$(MODEL_DIR):$(TB_DIR)/directed \
	    SIM=verilator \
	    TOPLEVEL=aes_top \
	    MODULE=test_aes_top \
	    KEY_BITS=$(KEY_BITS) \
	    VERILOG_SOURCES="$(RTL_DIR)/aes_pkg.sv $(RTL_DIR)/aes_key_expand.sv $(RTL_DIR)/aes_core.sv $(RTL_DIR)/aes_top.sv" \
	    COMPILE_ARGS="--sv +define+AES_KEY_BITS=$(KEY_BITS) -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-UNUSED -Wno-CASEINCOMPLETE -Wno-UNOPTFLAT -Wno-ASCRANGE" \
	    $(MAKE) -f Makefile.cocotb SIM_BUILD=sim_build_top_$(KEY_BITS)

sim-axil: $(BUILD_DIR)
	@echo "=== aes_axil cocotb sim (AES-$(KEY_BITS)) ==="
	cd $(SIM_DIR) && \
	    PATH="$(VENV)/bin:$$PATH" \
	    PYTHON_BIN="$(VENV)/bin/python3" \
	    PYTHONPATH=$(MODEL_DIR):$(TB_DIR)/directed \
	    SIM=verilator \
	    TOPLEVEL=aes_axil \
	    MODULE=test_aes_axil \
	    KEY_BITS=$(KEY_BITS) \
	    VERILOG_SOURCES="$(RTL_DIR)/aes_pkg.sv $(RTL_DIR)/aes_key_expand.sv $(RTL_DIR)/aes_core.sv $(RTL_DIR)/aes_top.sv $(RTL_DIR)/aes_axil.sv" \
	    COMPILE_ARGS="--sv +define+AES_KEY_BITS=$(KEY_BITS) -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-UNUSED -Wno-CASEINCOMPLETE -Wno-UNOPTFLAT -Wno-ASCRANGE" \
	    $(MAKE) -f Makefile.cocotb SIM_BUILD=sim_build_axil_$(KEY_BITS)

.PHONY: sim-128 sim-192 sim-256 sim-all-keys
sim-128:
	$(MAKE) sim KEY_BITS=128

sim-192:
	$(MAKE) sim KEY_BITS=192

sim-256:
	$(MAKE) sim KEY_BITS=256

sim-all-keys: sim-128 sim-192 sim-256
	@echo "=== All key sizes simulated ==="

.PHONY: sim-test
sim-test: $(BUILD_DIR)
	@echo "=== Running test: $(T) ==="
	cd $(SIM_DIR) && \
	    PYTHONPATH=$(MODEL_DIR):$(TB_DIR)/directed \
	    SIM=verilator \
	    TOPLEVEL=aes_top \
	    MODULE=test_aes_top \
	    TESTCASE=$(T) \
	    KEY_BITS=$(KEY_BITS) \
	    VERILOG_SOURCES="$(RTL_DIR)/aes_pkg.sv $(RTL_DIR)/aes_key_expand.sv $(RTL_DIR)/aes_core.sv $(RTL_DIR)/aes_top.sv" \
	    $(MAKE) -f Makefile.cocotb SIM_BUILD=sim_build_top

# ─────────────────────────────────────────────
# LiteX SoC build
# ─────────────────────────────────────────────
.PHONY: build
build:
	@echo "=== Building AES LiteX SoC (Vivado required) ==="
	source $(VENV)/bin/activate && \
	    cd $(LITEX_DIR) && \
	    $(PY) aes_soc.py --build \
	        --output-dir $(BUILD_DIR)/soc \
	        --no-compile-software

.PHONY: load
load:
	@echo "=== Loading bitstream to Arty A7 ==="
	source $(VENV)/bin/activate && \
	    cd $(LITEX_DIR) && \
	    $(PY) aes_soc.py --load \
	        --output-dir $(BUILD_DIR)/soc

.PHONY: build-load
build-load: build load

# ─────────────────────────────────────────────
# Hardware test via UART
# ─────────────────────────────────────────────
.PHONY: hw-test
hw-test:
	@echo "=== Running AES hardware test on $(UART_PORT) ==="
	source $(VENV)/bin/activate && \
	    $(PY) $(LITEX_DIR)/aes_uart_test.py \
	        --port $(UART_PORT)

# ─────────────────────────────────────────────
# Directory creation
# ─────────────────────────────────────────────
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ─────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(SIM_DIR)/sim_build*
	rm -rf $(SIM_DIR)/results.xml
	find . -name "*.vcd" -delete
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
