import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const SH_SECRET_IN_ARGV = /\b(?:curl|wget|nmcli|psql|mysql|gh|docker|sshpass|openssl)\b[^\n]*(?:--password|--token|--secret|-p\s+|\bAPI_KEY=)\s*["']?\$\{?[A-Z0-9_]*(?:PASS|PASSWORD|TOKEN|SECRET|API_KEY)[A-Z0-9_]*\}?["']?/g;
const SH_UNANCHORED_SHEBANG_GREP = /\bgrep\b[^\n]*#!\/usr\/bin\/env\b/g;
const SH_RELATIVE_PATH_EXPORT = /\bPATH=["']?(?:[^"'\n]*:)?(?:\.\/|\.\.\/|\.(?=:|\s|["']|$))/g;

const MCP_CONSOLE_LOG = /\bconsole\.log\s*\(/g;
const MCP_BODY_CANCEL = /\b(?:response|res)\.body\??\.cancel\s*\(\s*\)/g;
const MCP_THROW_ERROR = /\bthrow\s+new\s+McpError\s*\(/g;
const MCP_PY_STDOUT_LOG = /\blogging\.basicConfig\s*\(([^)\n]*)\)/g;
const AGENT_SPAWN_CALL = /\b(?:child_process\.)?spawn\s*\(/g;
const FILE_URI_STRIP = /\.\s*(?:strip_prefix|replace)\s*\(\s*["']file:\/\/["']/g;
const CMD_C_SPAWN = /\b(?:spawn|spawnSync|execFile|Command::new)\s*\(\s*["']cmd(?:\.exe)?["']\s*,[^)\n]*["']\/c["']/gi;
const SENSITIVE_FILE_PATH = /(?:secret|credential|token|auth|session|cookie|key|password)/i;
const TS_SENSITIVE_WRITE = /\bfs\.(?:writeFileSync|writeFile)\s*\(([^)\n]+)\)/g;
const PY_SENSITIVE_TEMP = /\bNamedTemporaryFile\s*\(([^)\n]*)\)/g;
const RUST_BYTE_SLICE_TRUNC = /&[A-Za-z_][A-Za-z0-9_.]*\s*\[\s*\.\.\s*[A-Za-z_][A-Za-z0-9_.]*(?:max|limit|len|cap|trunc)[A-Za-z0-9_]*\s*\]/gi;
const RUST_RKYV_UNCHECKED = /\brkyv::(?:access_unchecked|archived_root)\s*(?:::<|<|\()/g;
const LLM_RETRY_AFTER_SLEEP = /\b(?:sleep|setTimeout)\s*\(\s*(?:[^,\n]+,\s*)?(?:retryAfter|retryAfterMs|retry_after)\s*\)/g;
const PROMPT_CACHE_SORT_KEYS = /\bjson\.dumps\s*\([^)\n]*\bsort_keys\s*=\s*True\b/g;
const PROTO_GET_OWN_NAMES = /\bObject\.getOwnPropertyNames\s*\([^)\n]*\.prototype\s*\)/g;
const SYSTEM_PROMPT_NOW = /\b(?:systemPrompt|system_prompt)\b[^\n;]{0,120}(?:Date\.now\s*\(|new\s+Date\s*\(\s*\)|datetime\.(?:utc)?now\s*\()/g;

const MCP_PATH = /(?:^|\/)(?:mcp|stdio-server|jsonrpc|modelcontextprotocol)/i;
const PROMPT_OR_HISTORY_PATH = /(?:prompt|message|history|checkpoint|conversation|agent|llm)/i;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `W5:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function scanShellScript(file: ScannedFile, findings: Finding[]): void {
  const raw = file.content;
  const lines = raw.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (SH_SECRET_IN_ARGV.test(trimmed)) {
      SH_SECRET_IN_ARGV.lastIndex = 0;
      push(
        findings, file.rel, i + 1, "sh-secret-in-argv", "R0", "error",
        "Shell script passes secret/token variable via CLI argv (exposed to all local users via /proc/*/cmdline).",
        "Pass credentials through stdin, an environment variable, or a 0600 file descriptor instead of CLI arguments.",
      );
    }

    if (SH_UNANCHORED_SHEBANG_GREP.test(trimmed) && !/\bhead\s+-n\s*1\b/.test(trimmed)) {
      SH_UNANCHORED_SHEBANG_GREP.lastIndex = 0;
      push(
        findings, file.rel, i + 1, "sh-unanchored-shebang-grep", "R1", "warn",
        "Unanchored grep for '#!/usr/bin/env' scans entire files and misclassifies native binaries containing embedded strings.",
        "Inspect only the first line ('head -n 1 \"$bin\" | grep -Fq ...') when detecting script launchers.",
      );
    }

    if (SH_RELATIVE_PATH_EXPORT.test(trimmed)) {
      SH_RELATIVE_PATH_EXPORT.lastIndex = 0;
      push(
        findings, file.rel, i + 1, "sh-untrusted-path-in-sudo", "R0", "error",
        "Shell script adds a relative directory ('.' or './') to PATH, enabling binary hijacking.",
        "Use explicit absolute paths and pin PATH to trusted system directories.",
      );
    }
  }
}

export function analyzeWave5AiFirstGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;

  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    scanShellScript(file, findings);
    return findings;
  }

  if (!file.language || file.isTest) return findings;
  const code = maskCode(raw, file.language);
  const cfgTestIdx = file.language === "rust" ? raw.search(/#\[cfg\(test\)\]/) : -1;
  const prodCode = cfgTestIdx >= 0 ? code.slice(0, cfgTestIdx) : code;
  const prodRaw = cfgTestIdx >= 0 ? raw.slice(0, cfgTestIdx) : raw;

  for (const m of prodRaw.matchAll(FILE_URI_STRIP)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    const win = prodCode.slice(Math.max(0, idx - 120), idx + 180);
    if (/\b(?:to_file_path|fileURLToPath|win32|drive|trim_start_matches)\b/i.test(win)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "xplat-file-uri-strip-prefix", "R1", "warn",
      "Naive strip_prefix/replace('file://') leaves '/C:/...' broken on Windows.",
      "Convert file URIs using Url::to_file_path() (Rust) or node:url fileURLToPath() (TS/JS).",
    );
  }

  for (const m of prodRaw.matchAll(CMD_C_SPAWN)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    push(
      findings, file.rel, lineOf(raw, idx), "path-cmd-c-spawn", "R0", "error",
      "Spawning 'cmd /c' introduces shell-quoting and argument-injection bugs on Windows.",
      "Invoke the target executable directly with an explicit argument array without a shell wrapper.",
    );
  }

  for (const m of prodCode.matchAll(LLM_RETRY_AFTER_SLEEP)) {
    const idx = m.index ?? 0;
    const win = prodCode.slice(Math.max(0, idx - 220), idx + 80);
    if (/\b(?:Math\.min|min\(|clamp|MAX_RETRY|maxWait|maxDelay|maxBackoff)\b/i.test(win)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "llm-retry-after-unbounded", "R1", "warn",
      "Sleeping directly on server-supplied Retry-After without clamping can stall agents/workers for hours.",
      "Clamp retry-after durations with Math.min(retryAfterMs, MAX_RETRY_WAIT_MS) before sleeping.",
    );
  }

  for (const m of prodRaw.matchAll(SYSTEM_PROMPT_NOW)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    push(
      findings, file.rel, lineOf(raw, idx), "llm-prompt-cache-prefix-bust", "R1", "warn",
      "Interpolating live timestamps directly into static system prompts busts LLM prompt-cache prefixes on every turn.",
      "Keep static system prompts deterministic and inject volatile timestamps in a trailing user/turn context block.",
    );
  }

  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_BYTE_SLICE_TRUNC)) {
      const idx = m.index ?? 0;
      const win = prodCode.slice(Math.max(0, idx - 240), idx + 120);
      if (/\b(?:is_char_boundary|floor_char_boundary|chars\(\)|char_indices)\b/.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "tool-output-unicode-safe-truncation", "R1", "error",
        `Byte-slicing UTF-8 string (${m[0].trim()}) without is_char_boundary panics at runtime on multibyte Unicode/emoji.`,
        "Use floor_char_boundary() or char_indices() before slicing UTF-8 tool/file output.",
      );
    }

    for (const m of prodCode.matchAll(RUST_RKYV_UNCHECKED)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "rust-rkyv-require-bytecheck", "R0", "error",
        `Unchecked rkyv zero-copy deserialization (${m[0].trim()}) causes UB on corrupted or untrusted cache bytes.`,
        "Use rkyv::access::<ArchivedT, rancor::Error>() with bytecheck validation enabled.",
      );
    }
    return findings;
  }

  if (file.language === "python") {
    if (MCP_PATH.test(file.rel)) {
      for (const m of prodCode.matchAll(MCP_PY_STDOUT_LOG)) {
        const idx = m.index ?? 0;
        if (!/\bstream\s*=\s*sys\.stderr\b/.test(prodRaw.slice(idx, idx + 140))) {
          push(
            findings, file.rel, lineOf(raw, idx), "mcp-stdio-stdout-pollution", "R0", "error",
            "logging.basicConfig() in an MCP stdio module without stream=sys.stderr corrupts JSON-RPC stdout framing.",
            "Configure logging to write exclusively to sys.stderr (or a log file) in stdio MCP servers.",
          );
        }
      }
    }
    if (PROMPT_OR_HISTORY_PATH.test(file.rel)) {
      for (const m of prodCode.matchAll(PROMPT_CACHE_SORT_KEYS)) {
        push(
          findings, file.rel, lineOf(raw, m.index ?? 0), "llm-prompt-cache-prefix-bust", "R1", "warn",
          "json.dumps(..., sort_keys=True) in prompt/history serialization reorders keys and busts LLM prompt caches.",
          "Preserve insertion order when serializing message/tool histories to maximize prompt-cache hits.",
        );
      }
    }
    if (SENSITIVE_FILE_PATH.test(file.rel)) {
      for (const m of prodCode.matchAll(PY_SENSITIVE_TEMP)) {
        const idx = m.index ?? 0;
        const win = prodCode.slice(Math.max(0, idx - 120), idx + 220);
        if (/\b(?:0o600|os\.chmod|os\.open\b)\b/.test(win)) continue;
        push(
          findings, file.rel, lineOf(raw, idx), "sec-sensitive-file-default-umask", "R1", "warn",
          "Sensitive credential/session file created without enforcing 0o600 permissions.",
          "Create sensitive files atomically via os.open(..., 0o600) inside a 0o700 directory.",
        );
      }
    }
    return findings;
  }

  if (file.language !== "typescript" && file.language !== "javascript") return findings;

  if (MCP_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(MCP_CONSOLE_LOG)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "mcp-stdio-stdout-pollution", "R0", "error",
        "console.log() in an MCP stdio server writes to stdout and corrupts JSON-RPC framing.",
        "Log diagnostics via console.error() / process.stderr.write() in stdio MCP servers.",
      );
      break;
    }
    for (const m of prodCode.matchAll(MCP_THROW_ERROR)) {
      const idx = m.index ?? 0;
      const before = prodCode.slice(Math.max(0, idx - 260), idx);
      if (/\b(?:tool|callTool|registerTool)\b/i.test(before)) {
        push(
          findings, file.rel, lineOf(raw, idx), "mcp-throw-error-in-tool", "R1", "warn",
          "Throwing protocol-level McpError inside a tool callback breaks model self-correction loops.",
          "Return a tool result with { isError: true, content: [{ type: 'text', text: ... }] } for recoverable tool errors.",
        );
      }
    }
  }

  const isCloudflareWorker =
    /(?:^|\/)workers?\//i.test(file.rel) ||
    /\b(?:ExportedHandler|ExecutionContext|DurableObject|caches\.default|@cloudflare\/workers-types)\b/.test(raw);
  if (!isCloudflareWorker) {
    for (const m of prodCode.matchAll(MCP_BODY_CANCEL)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "mcp-body-cancel-hang", "R1", "warn",
        "Calling response.body.cancel() on HTTP/SSE responses can stall keep-alive connection pools.",
        "Drain unread response bodies via await response.text() / arrayBuffer() (with a size cap) or close the controller cleanly.",
      );
    }
  }

  for (const m of prodCode.matchAll(AGENT_SPAWN_CALL)) {
    const idx = m.index ?? 0;
    const after = prodCode.slice(idx, idx + 450);
    const rawAfter = prodRaw.slice(idx, idx + 450);
    if (!/\.on\s*\(\s*["']error["']|\.once\s*\(\s*["']error["']/.test(rawAfter) && !/\bspawnSync\b/.test(after)) {
      push(
        findings, file.rel, lineOf(raw, idx), "agent-subprocess-missing-error-handler", "R1", "warn",
        "Child process spawn() without an .on('error', ...) listener throws an uncaught ENOENT crash.",
        "Attach child.on('error', ...) immediately after spawn() and kill the process group (-pid) on teardown.",
      );
    }
  }

  if (SENSITIVE_FILE_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(TS_SENSITIVE_WRITE)) {
      const idx = m.index ?? 0;
      const win = prodRaw.slice(idx, idx + 220);
      if (/\bmode\s*:\s*0o?600\b/.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "sec-sensitive-file-default-umask", "R1", "warn",
        "Writing sensitive credential/session file without explicit { mode: 0o600 } exposes it under default umask.",
        "Pass { mode: 0o600 } directly to fs.writeFileSync/writeFile inside a 0o700 directory.",
      );
    }
  }

  for (const m of prodCode.matchAll(PROTO_GET_OWN_NAMES)) {
    const idx = m.index ?? 0;
    const after = prodRaw.slice(idx, idx + 220);
    if (/["']constructor["']/.test(after)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "js-prototype-copy-missing-constructor-skip", "R1", "warn",
      "Iterating Object.getOwnPropertyNames(*.prototype) without skipping 'constructor' crashes Hermes and strict runtimes.",
      "Skip 'constructor' when copying prototype descriptors.",
    );
  }

  return findings;
}
