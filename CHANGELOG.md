# Changelog

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
