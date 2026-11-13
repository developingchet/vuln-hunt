# `/vuln-hunt` isolation policy

Isolation is intentionally handled **outside** the Dynamic Workflow. A workflow boolean cannot create an OS security boundary.

## Why vuln-hunt does not force sandboxing for every static scan

The official Claude Security plugin itself states that it runs under the existing Claude Code session permissions and adds no isolation of its own. Its trust model is code you control; for an untrusted third-party repository, Anthropic suggests running the whole session inside `sandbox-runtime`.

That suggestion-only policy is sensible for trusted source. `/vuln-hunt` also targets authorized research against unfamiliar open-source code, so vuln-hunt documents a stronger recommendation for that case without pretending one isolation technology is universally available.

Forcing Claude Code's built-in command sandbox on every scan would create two problems:

1. it would reduce portability, especially on native Windows; and
2. it could create false confidence because the built-in sandbox controls shell-command execution, not every file tool, hook, MCP server, helper process or other session capability.

## Policy matrix

| Situation | Minimum policy |
|---|---|
| Trusted repository, static source reading only | isolation optional; least privilege and no unnecessary tools still preferred |
| Unfamiliar/third-party repository, static scan | whole-session isolation strongly recommended |
| Repository intentionally containing adversarial prompt/config content | whole-session isolation strongly recommended; disable unnecessary MCP/hooks/network capabilities |
| Build/test/fuzz/reproducer/target execution | disposable externally enforced whole-session/container/VM boundary required |
| Hostile native binaries or build system | disposable VM preferred |

## Built-in Claude Code sandbox

Useful as defense in depth, but not treated as sufficient for dynamic mode.

For strict command sandboxing in WSL/Linux, current Claude Code settings support fail-closed behavior such as:

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "allowNestedUserNamespaces": false
  }
}
```

Do not copy this blindly into an enterprise policy without checking current Claude Code documentation and your own required tools. `allowNestedUserNamespaces` is deliberately false because current documentation warns that enabling it can undermine filesystem isolation on Linux/WSL2.

Native Windows does not provide the same command sandbox; use WSL2, a container, sandbox-runtime where suitable, or a VM.

## Whole-process options

Current Claude Code documentation distinguishes broader isolation options:

- `sandbox-runtime`: wraps the full Claude Code process; currently documented as beta/research preview
- container: stronger process/filesystem separation when correctly configured
- dedicated VM/cloud session: strongest simple boundary for unfamiliar/hostile repositories

No option is secure merely because it has a label. Verify:

- no host credentials in environment or mounted home directories
- no Docker socket / privileged host control channel
- no sensitive host mounts
- no production tokens or SSH agents
- network egress disabled when not required
- bounded CPU/RAM/PIDs/time
- disposable filesystem/snapshot
- no inherited MCP/plugin/hook that escapes the intended boundary

## Dynamic mode contract

`/vuln-hunt` requires all of:

```json
{
  "mode": "dynamic",
  "containment": "vm",
  "network": false,
  "credentials": false
}
```

Accepted `containment` strings are `sandbox-runtime`, `container`, `vm`, and `cloud-session`.

This is an **operator assertion only**. The workflow cannot independently prove the VM/container/session configuration.

## Prompt injection versus isolation

Isolation and prompt-injection resistance solve different problems.

- Isolation limits what a compromised/misled agent or executed process can affect.
- Repository-content guards tell the model to treat `CLAUDE.md`, comments, fixtures, filenames and other repository text as evidence rather than instructions.

Keep both. Do not remove prompt-injection guards because a sandbox exists.

Research stages run as the read-only `vuln-hunt-researcher` worker (Read, Glob, Grep, `omitClaudeMd:true`), so a misled researcher cannot run commands, write files or reach the network. That limits what injected repository text can make a researcher do, but it is not containment. The mechanic and reporter workers can run commands, and in an ordinary session a subdirectory `CLAUDE.md` still loads when a worker reads files there. Starting the session through `vuln-hunt-launch.js` also drops project settings, hooks, `CLAUDE.md` files and MCP servers. Whole-session isolation is still what bounds a hostile repository.
