/** MOTOKO host tools. The shared motoko-host CLI owns the engine protocol. */
import { spawn } from "node:child_process";
import { lstat } from "node:fs/promises";
import { StringEnum, Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

const OPERATIONS = ["capabilities", "doctor", "rules", "digest", "query", "events", "health"] as const;
const KINDS = ["asset", "finding", "hypothesis", "evidence", "access", "path"] as const;
const STATES = [
	"active",
	"candidate",
	"triaged",
	"reproduced",
	"verified",
	"exploitable",
	"confirmed_impact",
	"false_positive",
	"duplicate",
	"out_of_scope",
	"wont_test",
	"proposed",
	"testing",
	"done",
	"rejected",
	"error",
	"timeout",
	"failed",
] as const;
const ERRORS = new Set([
	"invalid_arguments",
	"configuration_required",
	"runtime_permissions",
	"incompatible_engine",
	"invalid_response",
	"invalid_exit_status",
	"unsupported_platform",
	"transport_failed",
	"local_transport_failed",
	"invalid_request_or_result",
	"deadline_exceeded",
	"cancelled",
	"response_too_large",
	"engine_unavailable",
	"engagement_not_found",
	"engine_failed",
	"engine_closed_pipe",
]);
const MAX_FRAME = 65536;
const SAFE_ENV = new Set([
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TZ",
	"TMPDIR",
	"XDG_RUNTIME_DIR",
	"XDG_CONFIG_HOME",
	"XDG_CACHE_HOME",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"http_proxy",
	"https_proxy",
	"all_proxy",
	"no_proxy",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"ALL_PROXY",
	"NO_PROXY",
]);

async function configuredPaths(): Promise<[string, string]> {
	const executable = process.env.MOTOKO_HOST_EXECUTABLE;
	const config = process.env.MOTOKO_HOST_CONFIG;
	if (process.platform !== "linux") throw new Error("unsupported_platform");
	for (const value of [executable, config]) {
		if (!value?.startsWith("/") || value.includes("\0")) throw new Error("configuration_required");
	}
	try {
		const [exe, cfg] = await Promise.all([lstat(executable!), lstat(config!)]);
		if (!exe.isFile() || !(exe.mode & 0o111) || !cfg.isFile() || cfg.mode & 0o077 || cfg.uid !== process.getuid!()) {
			throw new Error("configuration_required");
		}
	} catch {
		throw new Error("configuration_required");
	}
	return [executable!, config!];
}

async function invoke(operation: string, params: Record<string, unknown>, signal?: AbortSignal) {
	const [executable, config] = await configuredPaths();
	if (signal?.aborted) throw new Error("cancelled");
	const { engagement_id, ...options } = params;
	const frame = `${JSON.stringify({ protocol: "motoko/1", operation, engagement_id, options })}\n`;
	if (Buffer.byteLength(frame) > MAX_FRAME) throw new Error("invalid_arguments");
	const seconds = Number(options.wall_timeout ?? (operation === "run" ? 600 : 90));
	if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 3600) throw new Error("invalid_arguments");
	const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => SAFE_ENV.has(key)));
	return await new Promise<Record<string, unknown>>((resolve, reject) => {
		const child = spawn(executable, ["--config", config, "--disconnect-cancels"], {
			env,
			cwd: "/",
			stdio: ["pipe", "pipe", "ignore"],
			detached: true,
		});
		let data = Buffer.alloc(0);
		let failure: string | undefined;
		let escalation: ReturnType<typeof setTimeout> | undefined;
		const stop = (reason: string) => {
			if (failure) return;
			failure = reason;
			child.kill("SIGTERM");
			// The shared client gets time to close its lease, await engine
			// cleanup, and reap its recorded group before escalation.
			escalation = setTimeout(() => {
				if (child.pid) {
					try {
						process.kill(-child.pid, "SIGKILL");
					} catch {
						/* Already exited. */
					}
				}
			}, 12000);
		};
		const cancel = () => stop("cancelled");
		const deadline = setTimeout(() => stop("deadline_exceeded"), (seconds + 35) * 1000);
		signal?.addEventListener("abort", cancel, { once: true });
		child.on("error", () => {
			failure = "transport_failed";
		});
		child.stdin.on("error", () => stop("transport_failed"));
		child.stdout.on("data", (chunk: Buffer) => {
			if (data.length + chunk.length > MAX_FRAME) {
				stop("response_too_large");
				return;
			}
			data = Buffer.concat([data, chunk]);
		});
		child.on("close", (code, termSignal) => {
			clearTimeout(deadline);
			if (escalation) clearTimeout(escalation);
			signal?.removeEventListener("abort", cancel);
			if (failure) {
				reject(new Error(failure));
				return;
			}
			try {
				const text = data.toString("utf8");
				if (!text.endsWith("\n") || text.split("\n").length !== 2 || termSignal) throw new Error();
				const result = JSON.parse(text);
				if (!result || typeof result !== "object" || Array.isArray(result) || typeof result.ok !== "boolean")
					throw new Error();
				if (!result.ok) {
					const error = result.error ?? result.result?.error;
					reject(new Error(ERRORS.has(error) ? error : "engine_failed"));
					return;
				}
				if (
					code !== 0 ||
					result.exit_code !== 0 ||
					result.protocol !== "motoko/1" ||
					result.operation !== operation
				)
					throw new Error();
				resolve(result);
			} catch {
				reject(new Error("invalid_response"));
			}
		});
		if (signal?.aborted) cancel();
		child.stdin.write(frame);
	});
}

const engagement = Type.String({
	pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
	description: "Existing authorized engagement identifier.",
});
const positive = (maximum: number, value?: number) =>
	Type.Integer({ minimum: 1, maximum, ...(value === undefined ? {} : { default: value }) });
const timeout = (value: number) => Type.Number({ exclusiveMinimum: 0, maximum: 3600, default: value });

export default function motoko(pi: ExtensionAPI) {
	pi.registerTool(
		defineTool({
			name: "motoko_status",
			label: "MOTOKO status",
			description:
				"Read MOTOKO capabilities and aggregate state without raw evidence. Check doctor and rules before a run.",
			parameters: Type.Object(
				{
					operation: StringEnum(OPERATIONS),
					engagement_id: Type.Optional(engagement),
					kind: Type.Optional(StringEnum(KINDS)),
					state: Type.Optional(StringEnum(STATES)),
					limit: Type.Optional(positive(100)),
					after: Type.Optional(Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })),
				},
				{ additionalProperties: false },
			),
			executionMode: "parallel",
			async execute(_id, params, signal) {
				const { operation, ...rest } = params;
				const result = await invoke(operation, rest, signal);
				return { content: [{ type: "text", text: JSON.stringify(result) }], details: result };
			},
		}),
	);
	pi.registerTool(
		defineTool({
			name: "motoko_run",
			label: "MOTOKO run",
			description:
				"Run a bounded wave budget for an existing authorized engagement. The engine selects tools and adapts priorities. Respect stop_reason and retry_after_s before resuming.",
			parameters: Type.Object(
				{
					engagement_id: engagement,
					max_cycles: Type.Optional(positive(1000, 20)),
					wave_cycles: Type.Optional(positive(100, 5)),
					max_waves: Type.Optional(positive(100, 4)),
					timeout: Type.Optional(timeout(300)),
					wall_timeout: Type.Optional(timeout(600)),
				},
				{ additionalProperties: false },
			),
			executionMode: "sequential",
			async execute(_id, params, signal) {
				const result = await invoke("run", params, signal);
				return { content: [{ type: "text", text: JSON.stringify(result) }], details: result };
			},
		}),
	);
}
