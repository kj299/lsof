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
	@echo "== matrix parses ==";    $(PY) -c "import tomllib; tomllib.load(open('$(H)/differential/input-matrix.example.toml','rb')); print('PASS  matrix parses')"
	@echo "== skills self-test =="; $(PY) skills/check_skills.py --self-test
	@echo "== skills integrity =="; $(PY) skills/check_skills.py
	@echo ""
	@echo "check-kit: ALL HARNESSES OK"

.PHONY: help
help:
	@echo "make check-kit   smoke-test every harness (python3 + bash only)"
