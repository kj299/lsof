# Porting Kit — smoke-test every harness so the kit itself never rots.
# `make check-kit` runs each harness's self-test; it needs only python3 + bash
# (no Rust toolchain), so it runs anywhere and gates changes to the kit.

PY := python3
H  := harnesses

.PHONY: check-kit
check-kit:
	@echo "== unsafe-audit ==";     $(PY) $(H)/unsafe-audit/audit_unsafe.py --self-test
	@# Contained, not just documented (LESSONS #065): the skeleton every port
	@# copies must itself forbid unsafe in core. lsof-rs's own crates are
	@# checked by lsof-rs-ci.yml, which control-coverage requires to call it.
	@echo "== forbid-unsafe self-test =="; $(PY) $(H)/unsafe-audit/check_forbid_unsafe.py --self-test
	@echo "== forbid-unsafe: the skeleton's core =="; $(PY) $(H)/unsafe-audit/check_forbid_unsafe.py skeleton/crates/core
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
	@# check_lesson_refs asks whether a cited entry exists; check_imports asks
	@# whether it is the entry the sentence means; this asks the other direction
	@# — does the FILE a lesson says it amended cite that lesson back? A lesson
	@# nothing pins is a note, not a control (LESSONS #033). --also-scan .. is
	@# not optional here: this kit is VENDORED, so the workflows lessons amend
	@# live one level up, and resolving only against the kit filed six live host
	@# files under "aged path(s) skipped" — four of them genuinely unpinned.
	@echo "== lessons pinned self-test =="; $(PY) $(H)/doc-check/check_lessons_pinned.py --self-test
	@echo "== lessons pinned ==";           $(PY) $(H)/doc-check/check_lessons_pinned.py . --also-scan ..
	@# Structure of the SHIPPED TEMPLATE, in --template mode: placeholders are
	@# expected there, a deleted section is not. The port's own filled-in copy
	@# is checked by lsof-rs-ci.yml, which is where a real port's gate belongs.
	@echo "== threat model ==";   $(PY) $(H)/threat-model/check_threat_model.py \
	    skeleton/THREAT-MODEL.md --template
	@# When two branches append to the log they take the same numbers, and the
	@# renumber that follows the merge is where citations go stale (LESSONS #048,
	@# #057). The resolver does that renumber from git, by line provenance. Its
	@# real run needs a merge in progress, so check-kit runs the self-test only.
	@echo "== collision resolver self-test =="; $(PY) $(H)/lessons/resolve_collision.py --self-test
	@# A port far slower than the C is a specific bug, not "the cost of Rust".
	@# Self-test only here: the real gate needs both binaries and a matrix.
	@echo "== perf gate ==";       $(PY) $(H)/perf/perf_gate.py --self-test
	@# Every control CLAUDE.md DECLARES must actually be invoked by the port's gate
	@# files, or exempted in writing with a reason. linux_diff.py is in the chain
	@# because it is what invokes diff_run.py.
	@echo "== control coverage =="; $(PY) $(H)/control-coverage/check_controls.py \
	    --controls CLAUDE.md --gate ../.github/workflows/lsof-rs-ci.yml \
	    --gate ../lsof-rs/differential/linux_diff.py
	@# Documented commands are code: they get pasted. Every `--flag` the operative
	@# docs attribute to a kit harness must exist in that harness's source.
	@echo "== doc flags ==";        $(PY) $(H)/doc-check/check_doc_flags.py .
	@# Toolchain-OPTIONAL: SKIPs cleanly with no cargo, so check-kit keeps its
	@# python3+bash-only minimum. With cargo it runs the REAL fmt/clippy/build/
	@# test against the skeleton every port starts by copying (LESSONS #044).
	@echo "== skeleton ==";         bash  $(H)/skeleton-check/check_skeleton.sh --check
	@# The gate above the gates: neutralize each gate's crown verdict in a scratch
	@# copy and require its own self-test to go red. A self-test that stays green
	@# over a dead verdict is pinning nothing. The sweep also AUDITS ITS OWN TABLE
	@# — any harness with a self-test and no mutation entry fails the run, so the
	@# survivor count cannot quietly describe a subset (LESSONS #050/#052).
	@echo "== gate-mutation self-test =="; $(PY) $(H)/gate-mutation/mutate_gates.py --self-test
	@echo "== gate-mutation sweep =="; $(PY) $(H)/gate-mutation/mutate_gates.py .
	@# The platform ledger. check_lesson_refs asks whether a cited entry exists;
	@# this asks whether every platform the BUILD SYSTEM can select is actually
	@# built by some CI provider, or waived on the record. It exists because
	@# LESSONS #049 found four of six lsof dialects were live tested platforms
	@# and three of them are tested by Cirrus and sourcehut — providers that
	@# never appear in a GitHub check list, so deleting their trees would have
	@# stayed green. The platform list is discovered from the tree, never read
	@# from the ledger, so adding a dialect and forgetting the ledger fails.
	@echo "== platform ledger self-test =="; $(PY) $(H)/platforms/check_platforms.py --self-test
	@echo "== platform ledger ==";           $(PY) $(H)/platforms/check_platforms.py
	@echo ""
	@echo "check-kit: ALL HARNESSES OK"

.PHONY: help
help:
	@echo "make check-kit   smoke-test every harness (python3 + bash only)"
