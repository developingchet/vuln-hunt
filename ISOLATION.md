# vuln-hunt isolation policy

Isolation is handled **outside** the workflow. A workflow option cannot create an operating-system security
boundary, so vuln-hunt documents which boundary each kind of scan needs and leaves enforcing it to the environment
Claude Code runs in.

## Why static scans do not force a sandbox

Anthropic's [Claude Security plugin](https://github.com/anthropics/claude-plugins-official/blob/main/plugins/claude-security/README.md)
runs under the existing Claude Code session permissions and adds no isolation of its own. Its trust model is code
you control; for a repository you do not trust, it suggests running the whole session inside
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime).

That is sensible for trusted source. vuln-hunt is also meant for authorized research on unfamiliar open-source
code, so it recommends more for that case, without pretending one isolation technology is available everywhere.

Forcing Claude Code's built-in sandbox on every scan would cause two problems:

1. it would not work everywhere: on native Windows, Claude Code runs commands unsandboxed; and
2. it would give false confidence, because the built-in sandbox covers shell commands, not file tools, hooks, MCP
   servers or other parts of the session
   ([what runs outside the sandbox](https://code.claude.com/docs/en/sandboxing#what-runs-outside-the-sandbox)).

## Policy

| Situation | Minimum policy |
|---|---|
| Trusted repository, static scan | isolation optional; least privilege and no unnecessary tools still preferred |
| Unfamiliar or third-party repository, static scan | whole-session isolation strongly recommended |
| Repository likely to contain adversarial prompts or configuration | whole-session isolation strongly recommended; start through the launcher; no unneeded MCP servers, hooks or network |
| Building, testing, fuzzing or running the target | disposable, externally enforced whole-session, container or VM boundary required |
| Hostile native binaries or build system | disposable VM preferred |

## Built-in Claude Code sandbox

The [sandbox](https://code.claude.com/docs/en/sandboxing) is useful defense in depth, but it is not enough for
dynamic mode. On macOS, Linux and WSL2 you can make it fail closed in your user settings:

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

Each key is described under [sandbox settings](https://code.claude.com/docs/en/settings-reference#sandbox).
Keep `allowNestedUserNamespaces` false: the documentation warns that turning it on "turns off a security boundary:
code from a sandboxed command can end up running outside the sandbox"
([Chromium or rootless Podman](https://code.claude.com/docs/en/sandboxing#chromium-or-rootless-podman-fails-inside-the-sandbox-on-linux)).
Check your own tools before copying this into a shared or managed policy.

On native Windows, use WSL2, a container, sandbox-runtime where it fits, or a VM.

## Whole-session options

| Option | Notes |
|---|---|
| [sandbox-runtime](https://code.claude.com/docs/en/sandbox-environments#sandbox-runtime) | Wraps the whole Claude Code process, including file tools, MCP servers and hooks. A beta research preview. |
| [Dev container](https://code.claude.com/docs/en/devcontainer) or [custom container](https://code.claude.com/docs/en/sandbox-environments#custom-container) | Separates processes and files from the host when configured correctly. Anything inside the container, including Claude Code's own credentials, is reachable by the code it runs. |
| [Virtual machine](https://code.claude.com/docs/en/sandbox-environments#virtual-machine) or a cloud session | The simplest strong boundary for unfamiliar or hostile repositories. |

No option is safe because of its name. Check that:

- no host credentials are in the environment or in mounted home directories
- no Docker socket or other privileged host control channel is reachable
- no sensitive host folders are mounted
- no production tokens or SSH agents are present
- outbound network access is off when it is not needed
- CPU, memory, process count and time are bounded
- the filesystem is disposable or snapshotted
- no inherited MCP server, plugin or hook reaches past the boundary

## Dynamic mode

Dynamic reproduction runs target code, so the workflow requires the operator to state the boundary it runs in:

```json
{
  "mode": "dynamic",
  "containment": "vm",
  "network": false,
  "credentials": false
}
```

`containment` is one of `sandbox-runtime`, `container`, `vm` or `cloud-session`, and `network` and `credentials`
must be `false`. This is the operator's assertion. The workflow cannot check the VM, container or session
configuration.

A `reproEnvironment` option describes a pre-built execution environment so reproduction needs no hand-edited
workflow script; it is a descriptor, not a boundary. `verifiedReady` is likewise the operator's assertion and is
recorded, never trusted. The boundary rules above still apply, and a descriptor that asks for host mounts,
credential paths or a Docker socket contradicts the boundary and should not be used. Prefer an image with the
target source baked in: a runtime mount over the image's prepared source both obscures it and reintroduces host
content into the execution boundary. A container with no host mounts can still hold secrets inherited from its
image or build process; treat image provenance as part of the boundary.

## Prompt injection and isolation

Isolation and prompt-injection resistance solve different problems:

- isolation limits what a misled agent, or code it runs, can affect;
- the prompts tell every agent to treat `CLAUDE.md`, comments, fixtures, file names and all other repository text as
  evidence, never instructions.

Keep both; a sandbox is not a reason to drop the guards.

Research stages run as the `vuln-hunt-researcher` worker, which has only Read, Glob and Grep and starts without
`CLAUDE.md`, so a misled researcher cannot run commands, write files or reach the network. That limits what injected
text can make a researcher do, but it is not containment: the mechanic and reporter workers can run commands, and in
an ordinary session a subdirectory `CLAUDE.md` still loads when a worker reads files there. Starting the session
through `vuln-hunt-launch.js` also leaves out project settings, hooks, `CLAUDE.md` files and MCP servers. For a
hostile repository, whole-session isolation is still what sets the limit.
