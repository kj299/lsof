# Porting Kit — smoke-test every harness so the kit itself never rots.
# `make check-kit` runs each harness's self-test; it needs only python3 + bash
# (no Rust toolchain), so it runs anywhere and gates changes to the kit.

PY := python3
H  := harnesses

.PHONY: check-kit
check-kit:
	@echo "== unsafe-audit ==";     $(PY) $(H)/unsafe-audit/audit_unsafe.py --self-test
	@echo "== normalize ==";        $(PY) $(H)/differential/normalize.py --self-test
	@echo "== diff_run ==";         $(PY) $(H)/differential/diff_run.py --self-test
	@echo "== golden ==";           $(PY) $(H)/golden/golden.py --self-test
	@echo "== c-flaw-scan ==";      $(PY) $(H)/c-flaw-scan/scan_c_flaws.py --self-test
	@echo "== progress ==";         $(PY) $(H)/progress/progress.py --self-test
	@echo "== fuzz scaffolder ==";  bash  $(H)/fuzz/gen_fuzz_target.sh --check
	@echo "== supply-chain ==";     bash  $(H)/supply-chain/run_supply_chain.sh --check
	@echo "== sanitizers ==";       bash  $(H)/sanitizers/run_sanitizers.sh --check
	@echo "== coverage gate ==";    $(PY) $(H)/coverage/coverage_gate.py --self-test
	@echo "== ledgers ==";          $(PY) $(H)/ledgers/check_ledgers.py --self-test
	@echo "== matrix parses ==";    $(PY) -c "import tomllib; tomllib.load(open('$(H)/differential/input-matrix.example.toml','rb')); print('PASS  matrix parses')"
	@echo "== inventory parses =="; $(PY) -c "import tomllib; d = tomllib.load(open('$(H)/coverage/feature-inventory-lsof.toml','rb')); print('PASS  lsof inventory parses (%d options, %d types)' % (len(d['features']['options']), len(d['features']['types'])))"
	@echo "== skills self-test =="; $(PY) skills/check_skills.py --self-test
	@echo "== skills integrity =="; $(PY) skills/check_skills.py
	@echo "== probe ==";           $(PY) $(H)/probe/probe.py --self-test
	@echo "== diff-fuzz ==";       $(PY) $(H)/diff-fuzz/diff_fuzz.py --self-test
	@echo "== lesson refs self-test =="; $(PY) $(H)/lessons/check_lesson_refs.py --self-test
	@# --also-scan .. : a citation is a claim wherever it is written, and the
	@# host repo cites lessons from CI workflows, backend sources, Cargo
	@# manifests and fuzz targets. Scanning only the kit left 52 of this repo's
	@# 214 citations checked by nothing.
	@echo "== lesson refs ==";          $(PY) $(H)/lessons/check_lesson_refs.py . --also-scan ..
	@# check_lesson_refs answers "does #14 exist?". Where this log has IMPORTED
	@# an entry from a sibling lineage of the kit, the numbers inside it came
	@# from a log that diverges from this one, so a number carried over verbatim
	@# still resolves and still means a different lesson. check_imports answers
	@# "is #14 the lesson this sentence means?" — the first import here shipped
	@# `#036/#14/#18/#20` with only the head re-cited, green through every gate.
	@echo "== imported lessons self-test =="; $(PY) $(H)/lessons/check_imports.py --self-test
	@echo "== imported lessons ==";           $(PY) $(H)/lessons/check_imports.py
	@# The gate above the gates: neutralize each gate's crown verdict in a scratch
	@# copy and require its own self-test to go red. A self-test that stays green
	@# over a dead verdict is pinning nothing. The sweep also AUDITS ITS OWN TABLE
	@# — any harness with a self-test and no mutation entry fails the run, so the
	@# survivor count cannot quietly describe a subset (LESSONS #049/#051).
	@# Toolchain-OPTIONAL: SKIPs cleanly with no cargo, so check-kit keeps its
	@# python3+bash-only minimum. With cargo it runs the REAL fmt/clippy/build/
	@# test against the skeleton every port starts by copying (LESSONS #044).
	@echo "== skeleton ==";         bash  $(H)/skeleton-check/check_skeleton.sh --check
	@echo "== gate-mutation self-test =="; $(PY) $(H)/gate-mutation/mutate_gates.py --self-test
	@echo "== gate-mutation sweep =="; $(PY) $(H)/gate-mutation/mutate_gates.py .
	@echo ""
	@echo "check-kit: ALL HARNESSES OK"

.PHONY: help
help:
	@echo "make check-kit   smoke-test every harness (python3 + bash only)"
