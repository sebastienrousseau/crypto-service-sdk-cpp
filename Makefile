# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# `make check` is the gate: version files, format, file size, the
# complexity ceilings, build with warnings as errors, tests (the
# conformance kit and live tests run when CRYPTO_SERVICE_URL is set, and
# skip otherwise), and clang-tidy. A missing clang-format, clang-tidy or
# rust-code-analysis-cli is reported and skipped locally; CI always has
# them. The gate builds the fuzz targets with a replay main and runs
# their seed corpus, and builds the benchmarks without running them
# (`make bench` runs them); `make fuzz` runs the fuzz targets under
# libFuzzer (clang with the compiler-rt fuzzer runtime, not Apple clang).

CMAKE        ?= cmake
CTEST        ?= ctest
CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy
RCA          ?= rust-code-analysis-cli
BUILD_DIR    ?= build
BUILD_TYPE   ?= Debug
CMAKE_ARGS   ?=
FUZZ_ARGS    ?= -DCRYPTO_SERVICE_SDK_BUILD_FUZZERS=ON -DCRYPTO_SERVICE_SDK_FUZZ_ENGINE=standalone
FUZZ_DIR     ?= build-fuzz
FUZZ_SECONDS ?= 30
FUZZ_FLAGS   ?= -fsanitize=address,undefined -fno-sanitize-recover=undefined
FUZZ_TARGETS  = response error
COV_DIR      ?= build-coverage
PKG_DIR      ?= build-package
BENCH_DIR    ?= build-bench
TSAN_DIR     ?= build-tsan
BENCH_ARGS   ?=
DOXYGEN      ?= doxygen
MKDOCS       ?= mkdocs
COV_FLAGS     = -fprofile-instr-generate -fcoverage-mapping -fprofile-update=atomic
LLVM_COV     ?= $(shell command -v llvm-cov 2>/dev/null || xcrun --find llvm-cov 2>/dev/null)
LLVM_PROFDATA ?= $(shell command -v llvm-profdata 2>/dev/null || xcrun --find llvm-profdata 2>/dev/null)

SOURCES = $(shell find include src tests examples fuzz benchmarks -type f \( -name '*.cpp' -o -name '*.hpp' \) | sort)
TIDY_SOURCES = $(shell find src tests examples fuzz benchmarks -type f -name '*.cpp' | sort)

.PHONY: check configure build test conformance examples readme-snippets bench regression docs demo \
        fuzz format format-check filesize versions complexity coverage package-test tsan tidy clean

check: versions format-check filesize complexity build test tidy

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	  -DCRYPTO_SERVICE_SDK_WERROR=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $(FUZZ_ARGS) \
	  -DCRYPTO_SERVICE_SDK_BUILD_BENCHMARKS=ON $(CMAKE_ARGS)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: build
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure

# The kit and the live tests only, and fail (not skip) without a server:
# CRYPTO_SERVICE_URL, CRYPTO_SERVICE_API_KEY and CRYPTO_SERVICE_JWT_SECRET
# (the server's JWT_SECRET, for the vectors that need given scopes).
conformance: build
	@test -n "$$CRYPTO_SERVICE_URL" || { echo "set CRYPTO_SERVICE_URL to a running crypto-server"; exit 1; }
	@test -n "$$CRYPTO_SERVICE_API_KEY" || { echo "set CRYPTO_SERVICE_API_KEY to the server's CRYPTO_API_KEY"; exit 1; }
	@test -n "$$CRYPTO_SERVICE_JWT_SECRET" || { echo "set CRYPTO_SERVICE_JWT_SECRET to the server's JWT_SECRET"; exit 1; }
	@status=0; $(BUILD_DIR)/tests/crypto_service_sdk_tests --gtest_filter='Kit/Conformance.*:Live.*' \
	  > $(BUILD_DIR)/conformance.log 2>&1 || status=$$?; \
	cat $(BUILD_DIR)/conformance.log; \
	test "$$status" -eq 0 && ! grep -q '\[  SKIPPED \]' $(BUILD_DIR)/conformance.log

# Every example against the server at CRYPTO_SERVICE_URL
# (scripts/run-examples.sh).
examples: build
	./scripts/run-examples.sh $(BUILD_DIR)

# Every C++ code block in README.md, compiled against the SDK and run
# against the server at CRYPTO_SERVICE_URL (scripts/readme-snippets.sh).
readme-snippets: build
	./scripts/readme-snippets.sh $(BUILD_DIR)

# Google Benchmark, Release build: encode_request, decode_response and
# decode_problem (no network), then round_trip_hash against
# CRYPTO_SERVICE_URL (skipped with a message when unset). CI passes a
# short BENCH_ARGS to smoke-run them; nothing is asserted.
bench:
	$(CMAKE) -S . -B $(BENCH_DIR) -DCMAKE_BUILD_TYPE=Release -DCRYPTO_SERVICE_SDK_BUILD_TESTS=OFF \
	  -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF -DCRYPTO_SERVICE_SDK_BUILD_BENCHMARKS=ON $(CMAKE_ARGS)
	$(CMAKE) --build $(BENCH_DIR) --parallel
	$(BENCH_DIR)/benchmarks/crypto_service_bench_client $(BENCH_ARGS)
	$(BENCH_DIR)/benchmarks/crypto_service_bench_loopback $(BENCH_ARGS)

# Everything against a real server at the pinned commit, which it builds,
# starts on a free loopback port and stops (scripts/regression.sh).
regression:
	./scripts/regression.sh

# The manual: Doxygen renders the headers into docs/api/ (warnings
# fail), then MkDocs builds site/ strictly. Install MkDocs with
# `pip install --require-hashes -r docs/requirements.txt`.
docs: configure
	rm -rf docs/api
	$(DOXYGEN) Doxyfile
	$(MKDOCS) build --strict

# libFuzzer with ASan and UBSan, FUZZ_SECONDS per target. New inputs go
# to $(FUZZ_DIR)/corpus, crash reproducers to $(FUZZ_DIR)/artifacts.
fuzz:
	$(CMAKE) -S . -B $(FUZZ_DIR) -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCRYPTO_SERVICE_SDK_WERROR=ON \
	  -DCRYPTO_SERVICE_SDK_BUILD_TESTS=OFF -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF \
	  -DCRYPTO_SERVICE_SDK_BUILD_FUZZERS=ON -DCRYPTO_SERVICE_SDK_FUZZ_ENGINE=libfuzzer \
	  "-DCMAKE_CXX_FLAGS=$(FUZZ_FLAGS)" "-DCMAKE_EXE_LINKER_FLAGS=$(FUZZ_FLAGS)"
	$(CMAKE) --build $(FUZZ_DIR) --parallel
	@mkdir -p $(FUZZ_DIR)/artifacts
	@for target in $(FUZZ_TARGETS); do \
	  mkdir -p $(FUZZ_DIR)/corpus/$$target; \
	  echo "== crypto_service_fuzz_$$target for $(FUZZ_SECONDS)s"; \
	  $(FUZZ_DIR)/fuzz/crypto_service_fuzz_$$target -max_total_time=$(FUZZ_SECONDS) \
	    -dict=fuzz/json.dict -artifact_prefix=$(FUZZ_DIR)/artifacts/$$target- \
	    -print_final_stats=1 $(FUZZ_DIR)/corpus/$$target fuzz/corpus/$$target || exit 1; \
	done

# Render .github/demo.gif with vhs. The tape runs the hash example
# against the server at CRYPTO_SERVICE_URL.
VHS ?= vhs

demo:
	@test -n "$$CRYPTO_SERVICE_URL" || { echo "demo: set CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY"; exit 1; }
	@command -v $(VHS) >/dev/null 2>&1 || { echo "demo: $(VHS) not found (https://github.com/charmbracelet/vhs)"; exit 1; }
	$(CMAKE) -S . -B build-demo -DCMAKE_BUILD_TYPE=Release -DCRYPTO_SERVICE_SDK_BUILD_TESTS=OFF
	$(CMAKE) --build build-demo --target crypto_service_hash --parallel
	$(VHS) .github/demo.tape

# Source-based coverage (clang for CC and CXX: GoogleTest enables C, and
# the link flags are clang's) of include/ and src/ from the unit tests
# alone, no server: fails below 100% line and branch. Exclusions are
# inline LCOV_EXCL markers with a reason (scripts/coverage-gate.py).
# Counters are atomic: the AsyncClient loop thread and the test thread
# run the same code, and plain counters lose increments, which skews
# the branch counts derived from them from run to run.
coverage:
	$(CMAKE) -S . -B $(COV_DIR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTO_SERVICE_SDK_WERROR=ON \
	  -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF "-DCMAKE_CXX_FLAGS=$(COV_FLAGS)" \
	  "-DCMAKE_EXE_LINKER_FLAGS=$(COV_FLAGS)" $(CMAKE_ARGS)
	$(CMAKE) --build $(COV_DIR) --parallel
	rm -f $(COV_DIR)/*.profraw
	env -u CRYPTO_SERVICE_URL LLVM_PROFILE_FILE=$(abspath $(COV_DIR))/cov-%p.profraw \
	  $(CTEST) --test-dir $(COV_DIR) --output-on-failure
	$(LLVM_PROFDATA) merge -sparse $(COV_DIR)/*.profraw -o $(COV_DIR)/coverage.profdata
	$(LLVM_COV) report $(COV_DIR)/tests/crypto_service_sdk_tests -instr-profile=$(COV_DIR)/coverage.profdata \
	  -ignore-filename-regex='/(_deps|tests|fuzz|examples|benchmarks)/' -show-branch-summary
	$(LLVM_COV) export $(COV_DIR)/tests/crypto_service_sdk_tests -instr-profile=$(COV_DIR)/coverage.profdata \
	  -ignore-filename-regex='/(_deps|tests|fuzz|examples|benchmarks)/' -format=lcov \
	  > $(COV_DIR)/coverage.lcov
	$(LLVM_COV) export $(COV_DIR)/tests/crypto_service_sdk_tests -instr-profile=$(COV_DIR)/coverage.profdata \
	  -ignore-filename-regex='/(_deps|tests|fuzz|examples|benchmarks)/' > $(COV_DIR)/coverage.json
	python3 scripts/coverage-gate.py $(COV_DIR)/coverage.lcov $(COV_DIR)/coverage.json

# Install into a staging prefix and build tests/package against it with
# find_package(crypto_service_sdk CONFIG): the installed package works.
package-test:
	$(CMAKE) -S . -B $(PKG_DIR)/sdk -DCMAKE_BUILD_TYPE=Release -DCRYPTO_SERVICE_SDK_BUILD_TESTS=OFF \
	  -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF $(CMAKE_ARGS)
	$(CMAKE) --build $(PKG_DIR)/sdk --parallel
	rm -rf $(PKG_DIR)/prefix
	$(CMAKE) --install $(PKG_DIR)/sdk --prefix $(abspath $(PKG_DIR))/prefix
	$(CMAKE) -S tests/package -B $(PKG_DIR)/consumer -DCMAKE_BUILD_TYPE=Release \
	  -DCMAKE_PREFIX_PATH=$(abspath $(PKG_DIR))/prefix
	$(CMAKE) --build $(PKG_DIR)/consumer
	$(PKG_DIR)/consumer/consumer

# ThreadSanitizer (clang): the AsyncClient and transport tests, which
# share clients across threads and destroy them with calls in flight.
tsan:
	$(CMAKE) -S . -B $(TSAN_DIR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTO_SERVICE_SDK_WERROR=ON \
	  -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF "-DCMAKE_CXX_FLAGS=-fsanitize=thread -O1 -g" \
	  "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread" $(CMAKE_ARGS)
	$(CMAKE) --build $(TSAN_DIR) --parallel
	env -u CRYPTO_SERVICE_URL TSAN_OPTIONS=halt_on_error=1 \
	  $(TSAN_DIR)/tests/crypto_service_sdk_tests --gtest_filter='AsyncClient.*:CurlMultiTransport.*:Operations.*:Client.*'

format:
	$(CLANG_FORMAT) -i $(SOURCES)

format-check:
	@if command -v $(CLANG_FORMAT) >/dev/null 2>&1; then \
	  $(CLANG_FORMAT) --dry-run --Werror $(SOURCES); \
	else echo "$(CLANG_FORMAT) not found: format check skipped (CI runs it)"; fi

filesize:
	./scripts/check-file-size.sh

versions:
	./scripts/verify-release-versions

# Cyclomatic 10, cognitive 15, Halstead difficulty 30, 60 lines per
# function (rust-code-analysis-cli 0.0.25; CI always has it).
complexity:
	@if command -v $(RCA) >/dev/null 2>&1; then \
	  python3 scripts/check-complexity.py --rca $(RCA); \
	else echo "$(RCA) not found: complexity check skipped (CI runs it)"; fi

tidy: configure
	@if command -v $(CLANG_TIDY) >/dev/null 2>&1; then \
	  $(CLANG_TIDY) -p $(BUILD_DIR) --quiet $(TIDY_SOURCES); \
	else echo "$(CLANG_TIDY) not found: clang-tidy skipped (CI runs it)"; fi

clean:
	rm -rf $(BUILD_DIR) $(FUZZ_DIR) $(COV_DIR) $(PKG_DIR) $(BENCH_DIR) $(TSAN_DIR) build-demo build-api \
	  build-snippets docs/api site
