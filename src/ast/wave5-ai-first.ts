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

interface W5FindingSpec {
  file: string;
  line: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: W5FindingSpec): void {
  findings.push({ id: `W5:${spec.rule}:${spec.file}:${spec.line}`, category: "structure", ...spec });
}

function scanShellScript(file: ScannedFile, findings: Finding[]): void {
  if (!file.content) return;
  const lines = file.content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = (lines[i] ?? "").trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (SH_SECRET_IN_ARGV.test(trimmed)) {
      SH_SECRET_IN_ARGV.lastIndex = 0;
      push(findings, {
        file: file.rel, line: i + 1, rule: "sh-secret-in-argv", rung: "R0", severity: "error",
        message: "Shell script passes secret/token variable via CLI argv (exposed to all local users via /proc/*/cmdline).",
        fix: "Pass credentials through stdin, an environment variable, or a 0600 file descriptor instead of CLI arguments.",
      });
    }
    if (SH_UNANCHORED_SHEBANG_GREP.test(trimmed) && !/\bhead\s+-n\s*1\b/.test(trimmed)) {
      SH_UNANCHORED_SHEBANG_GREP.lastIndex = 0;
      push(findings, {
        file: file.rel, line: i + 1, rule: "sh-unanchored-shebang-grep", rung: "R1", severity: "warn",
        message: "Unanchored grep for '#!/usr/bin/env' scans entire files and misclassifies native binaries containing embedded strings.",
        fix: "Inspect only the first line ('head -n 1 \"$bin\" | grep -Fq ...') when detecting script launchers.",
      });
    }
    if (SH_RELATIVE_PATH_EXPORT.test(trimmed)) {
      SH_RELATIVE_PATH_EXPORT.lastIndex = 0;
      push(findings, {
        file: file.rel, line: i + 1, rule: "sh-untrusted-path-in-sudo", rung: "R0", severity: "error",
        message: "Shell script adds a relative directory ('.' or './') to PATH, enabling binary hijacking.",
        fix: "Use explicit absolute paths and pin PATH to trusted system directories.",
      });
    }
  }
}

function scanCrossLangWave5(file: ScannedFile, prodCode: string, findings: Finding[]): void {
  if (!prodCode) return;
  const raw = file.content;
  for (const m of raw.matchAll(FILE_URI_STRIP)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " " || /\b(?:to_file_path|fileURLToPath|win32|drive|trim_start_matches)\b/i.test(prodCode.slice(Math.max(0, idx - 120), idx + 180))) continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "xplat-file-uri-strip-prefix", rung: "R1", severity: "warn",
      message: "Naive strip_prefix/replace('file://') leaves '/C:/...' broken on Windows.",
      fix: "Convert file URIs using Url::to_file_path() (Rust) or node:url fileURLToPath() (TS/JS).",
    });
  }
  for (const m of raw.matchAll(CMD_C_SPAWN)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "path-cmd-c-spawn", rung: "R0", severity: "error",
      message: "Spawning 'cmd /c' introduces shell-quoting and argument-injection bugs on Windows.",
      fix: "Invoke the target executable directly with an explicit argument array without a shell wrapper.",
    });
  }
  for (const m of prodCode.matchAll(LLM_RETRY_AFTER_SLEEP)) {
    const idx = m.index ?? 0;
    if (/\b(?:Math\.min|min\(|clamp|MAX_RETRY|maxWait|maxDelay|maxBackoff)\b/i.test(prodCode.slice(Math.max(0, idx - 220), idx + 80))) continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "llm-retry-after-unbounded", rung: "R1", severity: "warn",
      message: "Sleeping directly on server-supplied Retry-After without clamping can stall agents/workers for hours.",
      fix: "Clamp retry-after durations with Math.min(retryAfterMs, MAX_RETRY_WAIT_MS) before sleeping.",
    });
  }
  for (const m of raw.matchAll(SYSTEM_PROMPT_NOW)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "llm-prompt-cache-prefix-bust", rung: "R1", severity: "warn",
      message: "Interpolating live timestamps directly into static system prompts busts LLM prompt-cache prefixes on every turn.",
      fix: "Keep static system prompts deterministic and inject volatile timestamps in a trailing user/turn context block.",
    });
  }
}

function scanPythonWave5(file: ScannedFile, prodCode: string, findings: Finding[]): void {
  if (!prodCode) return;
  const raw = file.content;
  if (MCP_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(MCP_PY_STDOUT_LOG)) {
      const idx = m.index ?? 0;
      if (!/\bstream\s*=\s*sys\.stderr\b/.test(raw.slice(idx, idx + 140))) {
        push(findings, {
          file: file.rel, line: lineOf(raw, idx), rule: "mcp-stdio-stdout-pollution", rung: "R0", severity: "error",
          message: "logging.basicConfig() in an MCP stdio module without stream=sys.stderr corrupts JSON-RPC stdout framing.",
          fix: "Configure logging to write exclusively to sys.stderr (or a log file) in stdio MCP servers.",
        });
      }
    }
  }
  if (PROMPT_OR_HISTORY_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(PROMPT_CACHE_SORT_KEYS)) {
      push(findings, {
        file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "llm-prompt-cache-prefix-bust", rung: "R1", severity: "warn",
        message: "json.dumps(..., sort_keys=True) in prompt/history serialization reorders keys and busts LLM prompt caches.",
        fix: "Preserve insertion order when serializing message/tool histories to maximize prompt-cache hits.",
      });
    }
  }
  if (SENSITIVE_FILE_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(PY_SENSITIVE_TEMP)) {
      const idx = m.index ?? 0;
      if (/\b(?:0o600|os\.chmod|os\.open\b)\b/.test(prodCode.slice(Math.max(0, idx - 120), idx + 220))) continue;
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "sec-sensitive-file-default-umask", rung: "R1", severity: "warn",
        message: "Sensitive credential/session file created without enforcing 0o600 permissions.",
        fix: "Create sensitive files atomically via os.open(..., 0o600) inside a 0o700 directory.",
      });
    }
  }
}

function scanTsWave5(file: ScannedFile, prodCode: string, findings: Finding[]): void {
  if (!prodCode) return;
  const raw = file.content;
  if (MCP_PATH.test(file.rel)) {
    const isHttpOnlyMcp = /(?:http|sse|streamable)/i.test(file.rel) && !/\b(?:StdioServerTransport|process\.stdin|stdio)\b/i.test(raw);
    if (!isHttpOnlyMcp) {
      for (const m of prodCode.matchAll(MCP_CONSOLE_LOG)) {
        push(findings, {
          file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "mcp-stdio-stdout-pollution", rung: "R0", severity: "error",
          message: "console.log() in an MCP stdio server writes to stdout and corrupts JSON-RPC framing.",
          fix: "Log diagnostics via console.error() / process.stderr.write() in stdio MCP servers.",
        });
        break;
      }
    }
    for (const m of prodCode.matchAll(MCP_THROW_ERROR)) {
      const idx = m.index ?? 0;
      if (/\b(?:tool|callTool|registerTool)\b/i.test(prodCode.slice(Math.max(0, idx - 260), idx))) {
        push(findings, {
          file: file.rel, line: lineOf(raw, idx), rule: "mcp-throw-error-in-tool", rung: "R1", severity: "warn",
          message: "Throwing protocol-level McpError inside a tool callback breaks model self-correction loops.",
          fix: "Return a tool result with { isError: true, content: [{ type: 'text', text: ... }] } for recoverable tool errors.",
        });
      }
    }
  }
  const isCloudflareWorker = /(?:^|\/)workers?\//i.test(file.rel) || /\b(?:ExportedHandler|ExecutionContext|DurableObject|caches\.default|@cloudflare\/workers-types)\b/.test(raw);
  if (!isCloudflareWorker) {
    for (const m of prodCode.matchAll(MCP_BODY_CANCEL)) {
      push(findings, {
        file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "mcp-body-cancel-hang", rung: "R1", severity: "warn",
        message: "Calling response.body.cancel() on HTTP/SSE responses can stall keep-alive connection pools.",
        fix: "Drain unread response bodies via await response.text() / arrayBuffer() (with a size cap) or close the controller cleanly.",
      });
    }
  }
  const usesNodeChildProcess = /\bchild_process\b|\bimport\s*\{[^}]*\bspawn\b[^}]*\}\s*from\s*["'](?:node:)?child_process["']/.test(raw);
  for (const m of prodCode.matchAll(AGENT_SPAWN_CALL)) {
    const idx = m.index ?? 0;
    if ((!usesNodeChildProcess && !m[0].startsWith("child_process.")) || (idx > 0 && prodCode[idx - 1] === "." && !m[0].startsWith("child_process."))) continue;
    if (!/\.on\s*\(\s*["']error["']|\.once\s*\(\s*["']error["']/.test(raw.slice(idx, idx + 450)) && !/\bspawnSync\b/.test(prodCode.slice(idx, idx + 450))) {
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "agent-subprocess-missing-error-handler", rung: "R1", severity: "warn",
        message: "Child process spawn() without an .on('error', ...) listener throws an uncaught ENOENT crash.",
        fix: "Attach child.on('error', ...) immediately after spawn() and kill the process group (-pid) on teardown.",
      });
    }
  }
  if (SENSITIVE_FILE_PATH.test(file.rel)) {
    for (const m of prodCode.matchAll(TS_SENSITIVE_WRITE)) {
      const idx = m.index ?? 0;
      if (/\bmode\s*:\s*0o?600\b/.test(raw.slice(idx, idx + 220))) continue;
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "sec-sensitive-file-default-umask", rung: "R1", severity: "warn",
        message: "Writing sensitive credential/session file without explicit { mode: 0o600 } exposes it under default umask.",
        fix: "Pass { mode: 0o600 } directly to fs.writeFileSync/writeFile inside a 0o700 directory.",
      });
    }
  }
  for (const m of prodCode.matchAll(PROTO_GET_OWN_NAMES)) {
    const idx = m.index ?? 0;
    if (/["']constructor["']/.test(raw.slice(idx, idx + 220))) continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "js-prototype-copy-missing-constructor-skip", rung: "R1", severity: "warn",
      message: "Iterating Object.getOwnPropertyNames(*.prototype) without skipping 'constructor' crashes Hermes and strict runtimes.",
      fix: "Skip 'constructor' when copying prototype descriptors.",
    });
  }
}

export function analyzeWave5AiFirstGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  if (/\.(?:sh|bash)$/i.test(file.rel)) { scanShellScript(file, findings); return findings; }
  if (!file.language || file.isTest) return findings;
  const prodCode = maskCode(file.content, file.language, true);
  scanCrossLangWave5(file, prodCode, findings);
  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_BYTE_SLICE_TRUNC)) {
      const idx = m.index ?? 0;
      if (/\b(?:is_char_boundary|floor_char_boundary|chars\(\)|char_indices)\b/.test(prodCode.slice(Math.max(0, idx - 240), idx + 120))) continue;
      push(findings, {
        file: file.rel, line: lineOf(file.content, idx), rule: "tool-output-unicode-safe-truncation", rung: "R1", severity: "error",
        message: `Byte-slicing UTF-8 string (${m[0].trim()}) without is_char_boundary panics at runtime on multibyte Unicode/emoji.`,
        fix: "Use floor_char_boundary() or char_indices() before slicing UTF-8 tool/file output.",
      });
    }
    for (const m of prodCode.matchAll(RUST_RKYV_UNCHECKED)) {
      push(findings, {
        file: file.rel, line: lineOf(file.content, m.index ?? 0), rule: "rust-rkyv-require-bytecheck", rung: "R0", severity: "error",
        message: `Unchecked rkyv zero-copy deserialization (${m[0].trim()}) causes UB on corrupted or untrusted cache bytes.`,
        fix: "Use rkyv::access::<ArchivedT, rancor::Error>() with bytecheck validation enabled.",
      });
    }
    return findings;
  }
  if (file.language === "python") { scanPythonWave5(file, prodCode, findings); return findings; }
  if (file.language === "typescript" || file.language === "javascript") scanTsWave5(file, prodCode, findings);
  return findings;
}
