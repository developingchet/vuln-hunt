# Changelog

## 0.1.0 - unreleased

Reliability and evidence-integrity release.

- The attestation no longer passes through the session's model. `vuln-hunt-attest.js --emit-run` writes a private
  run directory outside the repository holding the attestation and a generated workflow script with the
  attestation embedded byte-for-byte, and `/vuln-hunt:scan` starts the workflow from that script's path. Array
  order and large range evidence survive transit unchanged; a run interrupted part-way can be resumed with the
  same script path. Passing the attestation as workflow arguments still works.
- `maxConcurrentAgents` (1-256) caps every agent this one run dispatches, including verification panels fanned
  out inside `pipeline()` and `parallel()` tasks and every retry. Admission is FIFO and a failed agent releases
  its slot. Rate-limit-classified failures get one paced retry through the gate; the native runtime ceiling still
  applies above the configured one.
- No candidate is silently dropped: every candidate's ledger entry ends in `VERIFIED`, `REJECTED`,
  `PREDATES_CHANGE`, `UNRESOLVED_EVIDENCE`, `UNRESOLVED_INFRASTRUCTURE` or `NOT_REACHED`. A missing
  verification vote is retried immediately, then once more in a recovery pass that retries only the missing
  seats, preserving all completed votes; a panel that still cannot complete is reported as unresolved by
  infrastructure with its missing seats named, never as a clean verdict.
- Citations are validated mechanically. The helper's new `--validate-citations` checks every researcher receipt
  and verifier citation against the attested manifest and real line counts, with an echoed input hash the
  workflow recomputes, so a nonexistent file, a prefix-matched directory or an impossible line number cannot
  support a verdict or a coverage receipt, and a tampered transport fails closed. Coverage gains a
  `receipt-thin` state (a 200-file unit needs more than one citation) and a `citationsValidated` status.
- `policyDocs` makes repository security-policy documents first-class: attested with `--policy-doc`, hashed into
  the state hash, and read by every researcher and verifier as untrusted evidence. A contradicted claim is
  evidence for a finding; a vulnerability the documents never mention is still reported; out-of-scope lists are
  disclosure-program metadata, not a filter. Attestation version 5 adds `policyDocs`; version 4 attestations are
  still accepted.
- Dynamic scanning is configurable without editing workflow scripts: a typed `reproEnvironment` descriptor
  (backend, image, locations, runtimes, entrypoints, instructions, limits, timeout) reaches the reproduction
  agent as structured data, `reproMinSeverity` selects which verified findings to reproduce, and reproduction
  statuses distinguish `REPRODUCED` from `NOT_REPRODUCED`, blocked, timeout and infrastructure failures. A generic
  passing test suite is environment readiness, never a reproduction; a failed reproduction never refutes a
  statically verified finding.
- Cross-run identity: each verified finding carries a deterministic `findingId`, and the helper's
  `--prior-findings` relates this run's findings to earlier runs' `findings.jsonl` as `REPRODUCED_AGAIN`,
  `TENTATIVE_MATCH` or `NEW`, with earlier findings left as `NOT_REASSESSED` rather than assumed fixed. Candidate
  IDs are per-run values and are never compared across runs alone.
- The written report is validated: `--validate-report` checks the report files exist, parse, and reconcile with
  the run's candidate and unit ledgers, with an echoed expectation hash. A closing freshness check flags a tree
  that changed during the run as `sourceChangedDuringRun`.
- The workflow returns a compact summary — identities, counts by status, coverage and reconciliation summaries,
  report-validation verdict — instead of duplicating the full report contents in the conversation.
- `runId` values of `.` and `..` are refused in the workflow and the helper's `--fingerprint`, closing a
  reserved-path escape.

## 0.0.1 - 2026-11-15

First release as a Claude Code plugin.

- Installs from the `developingchet/vuln-hunt` marketplace with `/plugin install vuln-hunt@vuln-hunt`, adding the
  `/vuln-hunt:vuln-hunt` workflow, the three worker agents, and the `/vuln-hunt:scan` and `/vuln-hunt:helpers`
  skills. `Install-VulnHunt.ps1` remains for installs without the plugin system.
- `/vuln-hunt:scan` attests the repository with the bundled helper and runs the workflow with strict provenance,
  for the whole tree or a Git range.
- The workflow prefers the plugin's workers, which a scanned repository cannot replace, and falls back to the
  bare worker names that the manual install and the launcher define.
- Workflow options are validated: options passed as a JSON string are parsed, and unknown keys, wrong types and
  out-of-range values are refused instead of replaced by defaults.
- The attestation treats assume-unchanged and skip-worktree entries as a dirty tree, refuses untracked nested Git
  repositories, rejects malformed ranges such as `A..B..C`, ignores the user's rename settings when listing a
  change, and accepts a working directory that differs from Git's root only in letter case or 8.3 form.
- The freshness check also confirms the helper and Node paths that ran, and its command works from Bash or
  PowerShell with quoted paths.
- A project agent that shadows a worker is refused however its frontmatter is written, including through linked
  directories.
- A missing worker inside a parallel stage stops the run with its name, and a report that cannot be written no
  longer discards the scan's result.
- PREDATES_CHANGE verdicts count only in change reviews, and the adjudicator sees the same change evidence as the
  panel.
- Released as a zip with a checksum file, both signed with cosign.
