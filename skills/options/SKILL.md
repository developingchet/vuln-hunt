---
name: options
description: List every vuln-hunt workflow option with its values, default and effect, the presets, and the forms /vuln-hunt:scan accepts them in. Use it to see what a scan can be told before running one.
allowed-tools:
  - Bash(node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-options.js":*)
---

Run this command once and print its output to the user exactly as it is, without summarising or reformatting it:

```
node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-options.js" --list
```

If it exits non-zero, show its error output verbatim.
