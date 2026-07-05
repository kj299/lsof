#!/usr/bin/env python3
"""Skills-integrity check — keeps the skills suite in lockstep with the kit.

Each skill in porting-kit/skills/<name>/SKILL.md is a thin invokable wrapper over
the kit's authoritative docs and real harness commands. The risk is *drift*: a
harness gets renamed or a flag changes, and a skill quietly points at something
that no longer exists. This check makes that a hard failure — it verifies:

  1. every SKILL.md has YAML frontmatter with `name:` and `description:`,
  2. the frontmatter `name` matches its directory name,
  3. every `porting-kit/<path>` a skill references actually exists in the kit.

Wired into `make check-kit`, so renaming a harness without updating the skills
(or the docs) breaks the build — the compounding-loop rule that the retrospective
must "keep the skills in integrity with the kit," enforced mechanically.

Usage:  check_skills.py [SKILLS_DIR]   (defaults to this file's directory)
        check_skills.py --self-test
"""
from __future__ import annotations

import os
import re
import sys

# A referenced kit path: porting-kit/<something with an extension or a dir>.
# Skip placeholders (<...>, *) and trailing punctuation/backticks.
PATH_RE = re.compile(r"porting-kit/[A-Za-z0-9_./-]+")
PLACEHOLDER = re.compile(r"[<>*`]")


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm = {}
    for line in text[3:end].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return fm


def check_skill(skill_dir, kit_root):
    problems = []
    name = os.path.basename(skill_dir.rstrip("/"))
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{name}: missing SKILL.md"]
    text = open(path, encoding="utf-8").read()

    fm = parse_frontmatter(text)
    if fm is None:
        problems.append(f"{name}: no YAML frontmatter (--- ... ---)")
    else:
        if not fm.get("name"):
            problems.append(f"{name}: frontmatter missing `name`")
        elif fm["name"] != name:
            problems.append(f"{name}: frontmatter name '{fm['name']}' != directory '{name}'")
        if not fm.get("description"):
            problems.append(f"{name}: frontmatter missing `description`")

    # Every referenced kit path must exist.
    for m in dict.fromkeys(PATH_RE.findall(text)):  # dedupe, keep order
        rel = m[len("porting-kit/"):].rstrip(".,);:")
        if not rel or PLACEHOLDER.search(m):
            continue
        if not os.path.exists(os.path.join(kit_root, rel)):
            problems.append(f"{name}: references missing kit path '{m}'")
    return problems


def run(skills_dir):
    kit_root = os.path.dirname(os.path.abspath(skills_dir.rstrip("/")))
    skill_dirs = sorted(
        os.path.join(skills_dir, d) for d in os.listdir(skills_dir)
        if os.path.isdir(os.path.join(skills_dir, d))
    )
    if not skill_dirs:
        print(f"no skills found under {skills_dir}")
        return 1
    all_problems = []
    for sd in skill_dirs:
        all_problems.extend(check_skill(sd, kit_root))
    for p in all_problems:
        print("PROBLEM: " + p)
    print(f"\n{len(skill_dirs)} skill(s) checked, {len(all_problems)} problem(s)")
    return 1 if all_problems else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "porting-kit")
        skills = os.path.join(kit, "skills")
        os.makedirs(os.path.join(kit, "harnesses"))
        open(os.path.join(kit, "PLAYBOOK.md"), "w").write("x")
        # good skill: valid frontmatter + only-existing refs
        good = os.path.join(skills, "good-skill"); os.makedirs(good)
        open(os.path.join(good, "SKILL.md"), "w").write(
            "---\nname: good-skill\ndescription: ok\n---\nsee porting-kit/PLAYBOOK.md\n")
        check("clean suite passes", run(skills) == 0)
        # bad skill: name mismatch + missing referenced path
        bad = os.path.join(skills, "bad-skill"); os.makedirs(bad)
        open(os.path.join(bad, "SKILL.md"), "w").write(
            "---\nname: WRONG\ndescription: d\n---\nrun porting-kit/harnesses/gone.py\n")
        check("name mismatch + missing path is caught", run(skills) == 1)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    skills_dir = argv[0] if argv else os.path.dirname(os.path.abspath(__file__))
    return run(skills_dir)


if __name__ == "__main__":
    sys.exit(main())
