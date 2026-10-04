// motoko seat plugin for opencode — control-plane adapter.
//
// Doctrine: the host is a configuration fact. This
// plugin is a THIN control plane: every tool shells out to the gated CLI
// (`motoko`), execution (strix sessions, shepherds) stays in systemd/timeout
// wrappers owned by the OS, never by this process. Plugin loaded = seat
// extended; plugin dead = seat degraded, line unaffected.
//
// Verified API surface (opencode 0.0.0-main-202609302229 as of 2026-10-01;
// surface unchanged since the 2026-09-28 check against 0.0.0-main-202609280832):
//   - `tool: { name: {description, args, execute} }` object registration
//   - plain-object args => every key required, NO runtime validation:
//     validate inside execute (repo carries no node_modules; zod unavailable)
//   - type-only imports are stripped by Bun — no package.json needed
//   - `tool.execute.before` throwing aborts the tool call
//   - plugins load at startup only; restart opencode after editing
//
// Ops-safe subset only (engine/core/cli.py inventory): digest/health/doctor/
// rules/query/events, strix (gated wrapper), ingest-strix, seal --verify,
// shepherd systemctl surface. init/kali/deploy/loop/recover stay engineer-side;
// `run` is deliberately NOT a tool (raw CLI has no wall-clock bound and
// max_waves defaults unbounded — the wall-clock bound lives in the seat
// adapter and the shepherd, not the CLI).
//
// The bash gate below is SEAT HARDENING layered on top of the real gates that
// live in the wrapper (six fail-closed checks) — it is not the anonymity
// boundary itself and does not attempt to defeat deliberate obfuscation
// (variable indirection, quote splicing). It stops accident-shaped raw
// launches and points the model at the gated paths.

import type { Plugin } from "@opencode-ai/plugin"
import { homedir } from "node:os"

// Seat-local binary resolved from the home directory, never a hardcoded
// absolute path; MOTOKO_BIN overrides for non-default installs.
const MOTOKO = process.env.MOTOKO_BIN ?? `${homedir()}/.local/bin/motoko`
const SYSTEMCTL = "/usr/bin/systemctl"
const UNIT_RE = /^strix-shepherd(-[a-z0-9-]+)?\.service$/

interface RunResult { code: number; out: string }

// Bounded subprocess run (post-kill pipe guard). If the child is
// killed (timeout/abort) but an orphaned descendant keeps the stdout/stderr
// pipes open, resolve after a 5s grace with an explicit unknown-state marker
// instead of hanging forever. No tool here owns a long-lived tree — strix
// sessions live under the wrapper's own pid/pgid, shepherds under systemd.
async function run(
  cmd: string[],
  args: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<RunResult> {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" })
  let killed = false
  const doKill = (sig: SIGKILL | SIGTERM) => {
    killed = true
    try { proc.kill(sig) } catch { /* already gone */ }
  }
  const timer =
    args.timeoutMs !== undefined
      ? setTimeout(() => doKill("SIGKILL"), args.timeoutMs)
      : undefined
  const onAbort = () => doKill("SIGTERM")
  args.signal?.addEventListener("abort", onAbort, { once: true })

  const work = Promise.all([
    new Response(proc.stdout).text().catch(() => ""),
    new Response(proc.stderr).text().catch(() => ""),
    proc.exited,
  ])
  // Guard: resolve 5s after a kill even if pipes never close.
  const stuck = (async (): Promise<null> => {
    while (!killed) await new Promise((r) => setTimeout(r, 100))
    await new Promise((r) => setTimeout(r, 5000))
    return null
  })()
  const settled = await Promise.race([work, stuck])
  let out: string, code: number
  if (settled === null) {
    out = "<output unresolved: child killed but a descendant still holds the pipe — assume UNKNOWN state and verify out-of-band>"
    code = -1
  } else {
    out = settled[0] + (settled[1] ? `\n[stderr]\n${settled[1]}` : "")
    code = settled[2]
  }
  if (timer !== undefined) clearTimeout(timer)
  args.signal?.removeEventListener("abort", onAbort)
  return { code, out }
}

function fail(msg: string): never {
  throw new Error(`motoko tool: ${msg}`)
}

function needString(v: unknown, name: string): string {
  if (typeof v !== "string" || v.length === 0) fail(`${name} must be a non-empty string`)
  return v
}

function needOneOf<T extends string>(v: unknown, name: string, allowed: readonly T[]): T {
  if (typeof v !== "string" || !(allowed as readonly string[]).includes(v))
    fail(`${name} must be one of: ${allowed.join(", ")}`)
  return v as T
}

export default (async () => ({
  tool: {
    // Read-side engine surface. `doctor` reads the CALLER's shell env — for a
    // live writer process audit /proc/<pid>/environ by hand (by design).
    motoko_status: {
      description:
        "MOTOKO engine read operations: digest (engagement context), health " +
        "(parked findings report), doctor (environment self-check), rules " +
        "(rule-corpus report), query (entity rows), events (event tail). " +
        "Use for any engine status question.",
      args: {
        operation: {
          type: "string",
          description: "digest|health|doctor|rules|query|events",
        },
        engagement: {
          type: "string",
          description: "engagement id (required except doctor/rules)",
        },
      },
      async execute(a: Record<string, unknown>, ctx) {
        const op = needOneOf(a.operation, "operation", [
          "digest", "health", "doctor", "rules", "query", "events",
        ] as const)
        const cmd =
          op === "doctor" || op === "rules"
            ? [MOTOKO, op]
            : [MOTOKO, op, needString(a.engagement, "engagement")]
        const r = await run(cmd, { signal: ctx.abort, timeoutMs: 120_000 })
        return {
          title: `motoko ${op}`,
          output: r.out.trim() || `(no output, exit ${r.code})`,
          metadata: { exit: r.code },
        }
      },
    },

    // The gated launch path. The CLI wrapper runs the six fail-closed gates
    // (the engine checkout's launch-strix.sh); this tool adds NOTHING permissive.
    // Budget 300s — gates 1-5 plus gate-6's wired window (env-raisable
    // via UPSTREAM_WIRED_TIMEOUT) can exceed 180s, and killing the wrapper
    // mid-gate-6 orphans a launched-but-unproven session (double-launch hazard).
    strix_launch: {
      description:
        "Launch a gated strix deep-dive via `motoko strix` (six fail-closed " +
        "anonymity gates, launch report written into the engagement dir). " +
        "Returns the launch report path + pid/pgid for later tree cleanup. " +
        "Never launch strix any other way.",
      args: {
        engagement: { type: "string", description: "engagement id" },
        target: { type: "string", description: "https://host (single-host discipline)" },
        mode: { type: "string", description: "deep|standard|quick" },
        egress_class: { type: "string", description: "egress class from deploy.json (e.g. uk)" },
        timeout_seconds: { type: "number", description: "session cap in seconds (900-7200)" },
      },
      async execute(a: Record<string, unknown>, ctx) {
        const eng = needString(a.engagement, "engagement")
        const target = needString(a.target, "target")
        if (!/^https:\/\/[A-Za-z0-9.-]+\/?$/.test(target))
          fail("target must be a single https://host URL (single-host discipline)")
        const mode = needOneOf(a.mode, "mode", ["deep", "standard", "quick"] as const)
        const egress = needString(a.egress_class, "egress_class")
        if (!/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(egress)) fail("bad egress_class shape")
        const t = a.timeout_seconds
        if (typeof t !== "number" || !Number.isInteger(t) || t < 900 || t > 7200)
          fail("timeout_seconds must be an integer in [900, 7200]")
        const r = await run(
          [
            MOTOKO, "strix", eng,
            "--target", target,
            "--mode", mode,
            "--egress-class", egress,
            "--timeout", String(t),
          ],
          { signal: ctx.abort, timeoutMs: 300_000 },
        )
        let output = r.out.trim()
        if (r.code === 137 || r.code === 143 || r.code === -1) {
          output +=
            `\n[WARNING] wrapper exit=${r.code} — the session may STILL have ` +
            `launched (the wrapper backgrounds it before the wired-marker ` +
            `window closes). Check <engagement>/strix_runs/launch-*.record ` +
            `for the pid/pgid BEFORE relaunching, or you will double-fire.`
        } else if (!output) {
          output = `wrapper exited ${r.code} with no output — treat as NOT launched and investigate`
        }
        return { title: `strix launch ${target}`, output, metadata: { exit: r.code, target, mode } }
      },
    },

    // Shepherd lifecycle. stop is destructive to a live scan — forced.
    shepherd_ctl: {
      description:
        "Manage strix shepherd systemd user units (pattern " +
        "strix-shepherd*.service, e.g. strix-shepherd-demo-a.service): " +
        "status / start / stop. stop kills the whole unit cgroup including " +
        "any live scan — requires force=true. Prefer letting a shepherd exit " +
        "by itself (ALL_DONE).",
      args: {
        action: { type: "string", description: "status|start|stop" },
        unit: { type: "string", description: "full unit name, e.g. strix-shepherd-demo-a.service" },
        force: { type: "boolean", description: "must be true for action=stop" },
      },
      async execute(a: Record<string, unknown>, ctx) {
        const action = needOneOf(a.action, "action", ["status", "start", "stop"] as const)
        const unit = needString(a.unit, "unit")
        if (!UNIT_RE.test(unit))
          fail(`unit must match ${UNIT_RE} (shepherd units only — no arbitrary systemd control)`)
        const force = a.force === true
        if (action === "stop" && !force)
          fail("stop requires force=true (it kills the live scan tree with the unit)")
        const verb = action === "status" ? "is-active" : action
        const r = await run([SYSTEMCTL, "--user", verb, unit], {
          signal: ctx.abort,
          timeoutMs: 60_000,
        })
        return { title: `shepherd ${action} ${unit}`, output: r.out.trim(), metadata: { exit: r.code } }
      },
    },

    // Reports back into the graph (idempotent, scope-guarded engine-side).
    ingest_strix: {
      description:
        "Ingest a strix penetration_test_report.md (or .log run artifacts) " +
        "into an engagement's graph via `motoko ingest-strix`. Idempotent; " +
        "out-of-scope hosts are rejected engine-side.",
      args: {
        engagement: { type: "string", description: "engagement id" },
        report: { type: "string", description: "path to the report file (.md/.log/.json/.sarif)" },
      },
      async execute(a: Record<string, unknown>, ctx) {
        const eng = needString(a.engagement, "engagement")
        const report = needString(a.report, "report")
        if (!/\.(md|log|json|sarif)$/.test(report))
          fail("report must be a .md/.log/.json/.sarif artifact path")
        const r = await run([MOTOKO, "ingest-strix", eng, report], {
          signal: ctx.abort,
          timeoutMs: 300_000,
        })
        return { title: `ingest ${report}`, output: r.out.trim(), metadata: { exit: r.code } }
      },
    },

    seal_verify: {
      description:
        "Consumer-side seal verification (`motoko seal <eng> --verify`): " +
        "sha256/size/schema reconciliation of a sealed engagement against " +
        "its manifest. Read-only.",
      args: { engagement: { type: "string", description: "engagement id" } },
      async execute(a: Record<string, unknown>, ctx) {
        const eng = needString(a.engagement, "engagement")
        const r = await run([MOTOKO, "seal", eng, "--verify"], {
          signal: ctx.abort,
          timeoutMs: 120_000,
        })
        return { title: `seal --verify ${eng}`, output: r.out.trim(), metadata: { exit: r.code } }
      },
    },
  },

  // Seat-hardening bash gate (per-segment, inspector-exempt).
  // Segmentation on [|;&\n] (the block-unsafe-kill precedent); per segment:
  //   - segments led by a read-only inspector (grep/pgrep/ls/tail/...) are
  //     inspection prose, exempt — `pgrep -af strix` and `grep strix x.log`
  //     are the seat's DAILY vocabulary and must not be blocked;
  //   - after stripping wrapper words (env/nohup/setsid/nice/sudo/command and
  //     timeout+args) and quote-normalizing the command word, a segment whose
  //     command is the strix binary is blocked;
  //   - `motoko strix ...` and `.../launch-strix.sh ...` are the gated paths
  //     and allowed — EXCEPT `--direct`, the legacy bare uplink escape the
  //     CLI deliberately refuses to expose (blocked even on the wrapper);
    //   - `motoko run ...` must carry --max-cycles or --timeout: the raw CLI
    //     has no wall clock and unbounded waves by default.
  // NOT in scope: variable indirection, quote splicing — deliberate
  // obfuscation is an operator problem, not a model-accident problem.
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return
    const cmd = String((output.args as { command?: unknown })?.command ?? "")
    if (!cmd) return
    const INSPECTORS = new Set([
      "grep", "egrep", "fgrep", "rg", "ls", "ll", "tail", "head", "cat", "wc",
      "stat", "file", "pgrep", "ps", "journalctl", "echo", "printf", "diff",
      "find", "sort", "uniq", "less", "which", "readlink", "date", "git",
      "systemctl",
    ])
    const WRAPPERS = new Set(["env", "nohup", "setsid", "nice", "sudo", "command"])
    for (const rawSeg of cmd.split(/[|;&\n]/)) {
      let seg = rawSeg.trim().replace(/^[(`({]+/, "")
      if (!seg) continue
      // strip leading wrapper words: env VAR=.. / nohup / nice -n .. / sudo /
      // timeout [flags] [duration] — for timeout, skip it plus every leading
      // token that is a flag or a number (covers `-k 10 5400 strix …`)
      let first = seg.split(/\s+/)[0].replace(/^["']|["']$/g, "")
      while (WRAPPERS.has(first) || first === "timeout" || /^[A-Za-z_][\w]*=/.test(first)) {
        if (first === "timeout") {
          const toks = seg.split(/\s+/)
          let i = 1
          while (i < toks.length && (/^-/.test(toks[i]) || /^\d+(\.\d+)?[smhd]?$/.test(toks[i]))) i++
          seg = toks.slice(i).join(" ")
        } else {
          seg = seg.split(/\s+/).slice(1).join(" ")
        }
        if (!seg) break
        first = seg.split(/\s+/)[0].replace(/^["']|["']$/g, "")
      }
      if (!seg) continue
      if (INSPECTORS.has(first)) continue        // inspection prose, not a launch
      const base = first.split("/").pop() ?? first
      if (first === "strix" || base === "strix") {
        throw new Error(
          "Blocked: raw strix invocation. Use the strix_launch tool or " +
            "`motoko strix` / launch-strix.sh — the gated paths (by design).",
        )
      }
      if (first === "motoko") {
        const second = seg.split(/\s+/)[1]
        if (second === "run" && !/--max-cycles|--timeout|--max-waves/.test(seg)) {
          throw new Error(
            "Blocked: unbounded `motoko run` (no wall clock, unbounded waves " +
              "by default). Pass --max-cycles / --timeout (by design).",
          )
        }
        // motoko strix / other motoko subcommands: allowed (strix is gated inside)
        continue
      }
      if (/launch-strix\.sh/.test(first)) {
        if (/(^|\s)--direct(\s|$)/.test(seg)) {
          throw new Error(
            "Blocked: --direct is the legacy bare uplink escape hatch, " +
              "operator-only and refused by the CLI wrapper by design.",
          )
        }
        continue
      }
    }
  },
})) satisfies Plugin
