---
name: helpers
description: Show the vuln-hunt launcher, attestation, prerequisite and postflight commands with this installation's paths filled in, when asked which commands to run by hand or how to check an installation.
disable-model-invocation: true
---

Print the following for the user exactly, as a short list of commands they can copy. Do not run any of
them. The paths below are this plugin installation's; they change when the plugin updates.

- Start Claude Code for a strict scan (from the repository root, in a terminal, not inside this session):
  `node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-launch.js"`
- Check the attestation helper's Git and Node capabilities (from an empty scratch Git repository):
  `node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-attest.js" --self-test`
- Generate a private run directory with the attestation and a generated workflow script, one `--policy-doc <path>`
  per security-policy document (from the repository root; add `--range main...HEAD` for a change review):
  `node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-attest.js" --emit-run`
- Attest the repository by hand, printing the attestation to the terminal (from its root):
  `node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-attest.js"`
- Compare the tree after a run with a saved attestation (pass the same `--range` and `--policy-doc` list):
  `node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-attest.js" --compare <saved-attestation.json>`
- Windows prerequisite check (PowerShell, from the repository root):
  `& "${CLAUDE_PLUGIN_ROOT}/Test-VulnHuntPrereqs.ps1"`

Then add one line: inside a session started by the launcher, run `/vuln-hunt:scan` to attest and scan.
