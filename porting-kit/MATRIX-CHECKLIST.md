# Designing the differential matrix

Detail pushed out of PLAYBOOK Phase 4, step 2, which keeps a summary and the
lessons it cites. A green differential is a statement about the matrix, not
the port: it checks the inputs the matrix holds. Each item below is an input
that tells two readings of a rule apart, and each was learnt by lsof-rs the
expensive way — a rule written from a model of the C, matched on every case
the matrix could spell, and wrong on the first case it could not.

A **C-DEFECT** below is a divergence where the C is wrong and the port
deliberately does not follow it: it stays in the ledger, because the oracle
keeps disagreeing, and names the C code so anyone can check the triage.

## The surface

- **Every feature the C has gets a case**, enforced by
  `harnesses/coverage/coverage_gate.py`: bootstrap the inventory from the C
  (`--extract-options`/`--extract-types`), curate it, and the gate exits 1 on
  any feature no matrix case exercises; waivers carry reasons and can be
  scoped to a platform (LESSONS #6, #8, #18).
- **A value-taking option counts twice**: getopt offers it two spellings, the
  value attached (`-Fpn`) and as the next word (`-F pn`), and a port can parse
  one of them. The gate requires both (LESSONS #071).
- **What the tool cannot see is a feature too.** A harness that can read every
  fixture never compares what the tool prints when it cannot read one, and for
  a tool that reports on system state that path is output. Give the matrix a
  fixture the tool cannot read, run those cases as a user who cannot read it,
  probe that from the demoted side, and SKIP by name when it does not hold
  (LESSONS #068).

## Inputs that tell two readings apart

- **A fallback is a feature of its own** (LESSONS #075). For each fallback,
  exemption or second matching rule, name the input it is for, and give the
  matrix a case where it must fire for that input and one where another input
  must not reach it. lsof-rs compared NAMEs to find sockets by path; a
  socket's NAME carries a `type=` tail, so the comparison never found one and
  fired only for a file of the same name in another mount namespace.
- **An empty list item is input too** (LESSONS #076). For every list-valued
  option: an empty item in each position (`,`, `,x`, `x,`, `x,,y`), a lone
  prefix (`^`), a separator the oracle does not name, a repeated option, and
  items of mixed kinds. lsof-rs split its lists with
  `filter(|s| !s.is_empty())`, and the C read an empty `-p` item as PID 0.
- **Spell a path every way a user types it** (LESSONS #077): relative (a case
  names the directory it runs in, `cwd`), `.`, `..`, doubled and trailing
  slashes, links with relative and absolute targets, a link's text (`/proc`).
  Where the C spells or parses an input with a helper of its own, port the
  helper, and compile the C's own function into a harness as its oracle.
- **A silent case needs a reason to be silent** (LESSONS #26, #078). A case
  whose expected outcome is silence — an error exit, an empty listing, a
  suppressed column — can be met by many wrong programs. lsof-rs's `lsof -K x`
  case compared an empty stdout and an exit 1 that the two binaries reached
  for opposite reasons. A case that claims something about what is listed
  needs something to list that the claim would change, and a C-DEFECT that
  depends on where an argument stands needs the options first, where the C
  reads them as options.
- **A fixture changes what other cases see** (LESSONS #081). A fixture that
  changes shared state — the mount table, `/dev/shm`, a sysctl, the lock
  table — is an input to every case. Give what it makes names nothing else
  uses, undo it in the harness's `finally`, and judge a new fixture by the
  whole matrix, never by its own cases.

## Where the matrix runs out

The matrix holds the cases someone thought of. Fuzz the same inputs into the
oracle and the port with `harnesses/diff-fuzz/diff_fuzz.py`: on stdin, or for a
command-line tool on argv, from the coverage inventory's option letters
(`--argv-inventory`, LESSONS #084). Its first run against lsof-rs found four
divergences no case had (lsof-rs DIVERGENCES 114–117).

## Proving the cases

Mutate the rules the cases are for (LESSONS #26): one plausible wrong version
of each, committed as a mutants file beside the cases and run with
`harnesses/port-mutation/mutate_port.py` (LESSONS #083). Every mutant must be
KILLED. A survivor is a case that checks nothing, and an edit that does not
apply, or a mutant left in place, is refused by the harness rather than read
as a result (LESSONS #059, #066).
