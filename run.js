#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  elastic-unified-demo — Unified Ingest Launcher
 * ══════════════════════════════════════════════════════════════════════════════
 *
 *  Single entry point that combines two existing, unmodified data sets:
 *
 *    A) Elastic Security POC Simulator   (simulator/)
 *         Synthetic ECS events, attack scenarios, alerts and an investigation
 *         case — generated straight into Elasticsearch.
 *         Original scripts: demo-walkthrough.js / sample-data.js
 *
 *    B) Elastic Security Demo with AI    (demo-logs/)
 *         PA PAN-OS + Windows + Linux NDJSON demo logs backing the
 *         "Operation Silent Pivot" / "Quiet Insider" walkthrough.
 *         Original scripts: generate_all_demo_logs.cjs / ingest_all_demo_logs.cjs
 *
 *  This launcher does NOT change the logic of either original script. It only:
 *    1. asks which Elastic deployment to target,
 *    2. loads the matching credentials from credentials.txt,
 *    3. exports them as environment variables, and
 *    4. runs the original scripts as child processes.
 *
 *  Usage:
 *    node run.js                                  interactive (recommended)
 *    node run.js --target cloud_hosted --task both --yes
 *    node run.js --cleanup                        remove all demo + sample data
 *
 *  Flags:
 *    --target  serverless | cloud_hosted | self_managed
 *    --task    simulator | demo-logs | both | cleanup
 *    --regenerate / --no-regenerate   control NDJSON regeneration
 *    --yes, -y   skip confirmation prompts
 *    --help, -h
 * ══════════════════════════════════════════════════════════════════════════════
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require_ = createRequire(import.meta.url);
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SIM_DIR = path.join(ROOT, "simulator");
const LOGS_DIR = path.join(ROOT, "demo-logs");
const CRED_FILE = path.join(ROOT, "credentials.txt");

// ═══════════════════════════════════════════════════════════════════════════
// TARGETS
// ═══════════════════════════════════════════════════════════════════════════

const TARGETS = {
  1: { key: "serverless", label: "Elastic Cloud Serverless" },
  2: { key: "cloud_hosted", label: "Elastic Cloud Hosted" },
  3: { key: "self_managed", label: "Elastic Self-Managed (on-premise / Docker / local)" },
};

const TASKS = {
  1: { key: "simulator", label: "POC Simulator only — synthetic events, attack scenarios, alerts, case" },
  2: { key: "demo-logs", label: "Demo walkthrough logs only — PA PAN-OS + Windows + Linux NDJSON" },
  3: { key: "both", label: "Both (recommended for a full demo environment)" },
  4: { key: "cleanup", label: "Cleanup — remove all previously ingested demo & sample data" },
};

// ═══════════════════════════════════════════════════════════════════════════
// SMALL HELPERS
// ═══════════════════════════════════════════════════════════════════════════

const c = {
  b: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

function banner() {
  console.log("");
  console.log(c.b("╔══════════════════════════════════════════════════════════════╗"));
  console.log(c.b("║   Elastic Security — Unified Demo Data Ingest                ║"));
  console.log(c.b("║   POC Simulator  +  Demo Walkthrough Logs                    ║"));
  console.log(c.b("╚══════════════════════════════════════════════════════════════╝"));
  console.log("");
}

// ── Minimal line reader ────────────────────────────────────────────────────
// Deliberately not node:readline. A readline interface closes as soon as a piped
// stdin reaches EOF, which breaks the second prompt when input is piped in
// (e.g. `printf '3\n1\ny\n' | node run.js`). This queues whole lines instead and
// releases stdin between questions so child processes can use it.
let stdinBuf = "";
const lineQueue = [];
let pendingResolve = null;
let reading = false;
let endHooked = false;

function onStdinData(chunk) {
  stdinBuf += chunk;
  let i;
  while ((i = stdinBuf.indexOf("\n")) >= 0) {
    const line = stdinBuf.slice(0, i).replace(/\r$/, "");
    stdinBuf = stdinBuf.slice(i + 1);
    deliver(line);
  }
}

function deliver(line) {
  if (pendingResolve) {
    const resolve = pendingResolve;
    pendingResolve = null;
    stopReading();
    resolve(line);
  } else {
    lineQueue.push(line);
  }
}

function startReading() {
  if (reading) return;
  reading = true;
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", onStdinData);
  process.stdin.resume();
  if (!endHooked) {
    endHooked = true;
    process.stdin.on("end", () => {
      if (stdinBuf.trim()) { const last = stdinBuf.trim(); stdinBuf = ""; deliver(last); }
      else if (pendingResolve) { const r = pendingResolve; pendingResolve = null; stopReading(); r(""); }
    });
  }
}

function stopReading() {
  if (!reading) return;
  reading = false;
  process.stdin.off("data", onStdinData);
  process.stdin.pause();
}

function closeReadline() {
  stopReading();
}

function ask(question) {
  process.stdout.write(question);
  if (lineQueue.length) {
    const line = lineQueue.shift();
    process.stdout.write(line + "\n");
    return Promise.resolve(line.trim());
  }
  return new Promise((resolve) => {
    pendingResolve = (line) => resolve(line.trim());
    startReading();
  });
}

async function confirm(message, skip) {
  if (skip) return true;
  const a = await ask(`${message} [y/N] `);
  return a.toLowerCase() === "y" || a.toLowerCase() === "yes";
}

function fail(msg) {
  console.error("\n" + c.red("✗ " + msg) + "\n");
  process.exit(1);
}

function mask(v) {
  if (!v) return "(not set)";
  return v.length <= 8 ? "********" : v.slice(0, 4) + "…" + v.slice(-4);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREDENTIALS FILE PARSER
//
// Reads credentials.txt (NOT a .env file — parsed here, no dotenv needed).
// Format:  [section]  /  KEY = value  /  # comment
// ═══════════════════════════════════════════════════════════════════════════

function parseCredentials(file) {
  if (!fs.existsSync(file)) {
    fail(
      `credentials.txt not found.\n\n` +
        `  Create it from the template, then fill in the section for your deployment:\n\n` +
        `    cp credentials.example.txt credentials.txt\n\n` +
        `  credentials.txt is git-ignored, so your keys never get committed.`
    );
  }

  const sections = {};
  let current = null;

  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (let raw of lines) {
    let line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith(";")) continue;

    const sec = line.match(/^\[([A-Za-z0-9_\-]+)\]$/);
    if (sec) {
      current = sec[1].toLowerCase();
      sections[current] = sections[current] || {};
      continue;
    }

    // strip trailing inline comment (but keep '#' inside a value-less line)
    const hash = line.indexOf(" #");
    if (hash > -1) line = line.slice(0, hash).trim();

    const eq = line.indexOf("=");
    if (eq === -1 || !current) continue;

    const key = line.slice(0, eq).trim().toUpperCase();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (value) sections[current][key] = value;
  }

  return sections;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLOUD ID DECODER  (same algorithm as the original ingest script)
// ═══════════════════════════════════════════════════════════════════════════

function decodeCloudId(cloudId) {
  try {
    const b64 = cloudId.split(":")[1];
    const parts = Buffer.from(b64, "base64").toString("utf8").split("$");
    return {
      es: `https://${parts[1]}.${parts[0]}`,
      kibana: parts[2] ? `https://${parts[2]}.${parts[0]}` : null,
    };
  } catch {
    return { es: null, kibana: null };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILD THE ENVIRONMENT HANDED TO THE ORIGINAL SCRIPTS
// ═══════════════════════════════════════════════════════════════════════════

function buildEnv(targetKey, cfg) {
  // Start from a clean slate so stale shell exports can never leak into a run.
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith("ELASTICSEARCH_") || k.startsWith("KIBANA_")) delete env[k];
  }

  let esUrl = cfg.ELASTICSEARCH_URL || "";
  let kbUrl = cfg.KIBANA_URL || "";
  const cloudId = targetKey === "cloud_hosted" ? cfg.ELASTICSEARCH_CLOUD_ID || "" : "";

  if (cloudId) {
    const decoded = decodeCloudId(cloudId);
    if (!decoded.es) fail("ELASTICSEARCH_CLOUD_ID in credentials.txt could not be decoded.");
    if (!esUrl) esUrl = decoded.es;
    if (!kbUrl && decoded.kibana) kbUrl = decoded.kibana;
    env.ELASTICSEARCH_CLOUD_ID = cloudId;
  }

  if (!esUrl) {
    fail(
      `No Elasticsearch endpoint for [${targetKey}] in credentials.txt.\n` +
        (targetKey === "cloud_hosted"
          ? "  Set ELASTICSEARCH_CLOUD_ID (or ELASTICSEARCH_URL)."
          : "  Set ELASTICSEARCH_URL.")
    );
  }

  const apiKey = cfg.ELASTICSEARCH_API_KEY || "";
  const user = cfg.ELASTICSEARCH_USERNAME || "";
  const pass = cfg.ELASTICSEARCH_PASSWORD || "";

  if (!apiKey && !(user && pass)) {
    fail(
      `No credentials for [${targetKey}] in credentials.txt.\n` +
        "  Set ELASTICSEARCH_API_KEY, or ELASTICSEARCH_USERNAME + ELASTICSEARCH_PASSWORD."
    );
  }

  env.ELASTICSEARCH_URL = esUrl;
  if (apiKey) env.ELASTICSEARCH_API_KEY = apiKey;
  if (user) env.ELASTICSEARCH_USERNAME = user;
  if (pass) env.ELASTICSEARCH_PASSWORD = pass;

  if (kbUrl) env.KIBANA_URL = kbUrl;
  // Kibana falls back to the Elasticsearch API key when no dedicated one is given.
  const kbKey = cfg.KIBANA_API_KEY || apiKey;
  if (kbKey) env.KIBANA_API_KEY = kbKey;
  if (cfg.KIBANA_SPACE_ID) env.KIBANA_SPACE_ID = cfg.KIBANA_SPACE_ID;

  // TLS handling for self-signed certificates (self-managed clusters).
  const verifySsl = String(cfg.VERIFY_SSL ?? "true").toLowerCase();
  if (verifySsl === "false" || verifySsl === "no" || verifySsl === "0") {
    env.ELASTICSEARCH_INSECURE = "true";
    env.KIBANA_INSECURE = "true";
    env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // for this process's own checks
  }
  if (cfg.CA_CERT && fs.existsSync(cfg.CA_CERT)) {
    env.NODE_EXTRA_CA_CERTS = cfg.CA_CERT;
    process.env.NODE_EXTRA_CA_CERTS = cfg.CA_CERT;
  }

  return { env, esUrl, kbUrl, apiKey, user };
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION CHECK
// ═══════════════════════════════════════════════════════════════════════════

function authHeader(env) {
  if (env.ELASTICSEARCH_API_KEY) return `ApiKey ${env.ELASTICSEARCH_API_KEY}`;
  const basic = Buffer.from(`${env.ELASTICSEARCH_USERNAME}:${env.ELASTICSEARCH_PASSWORD}`).toString("base64");
  return `Basic ${basic}`;
}

async function checkElasticsearch(env, esUrl) {
  try {
    const res = await fetch(esUrl.replace(/\/$/, "") + "/", {
      headers: { Authorization: authHeader(env), "Content-Type": "application/json" },
    });
    if (!res.ok) {
      console.log(c.red(`  ✗ Elasticsearch responded HTTP ${res.status}`));
      if (res.status === 401 || res.status === 403) {
        console.log(c.dim("    Check ELASTICSEARCH_API_KEY / username + password in credentials.txt."));
      }
      return false;
    }
    const body = await res.json();
    console.log(c.green(`  ✓ Elasticsearch ${body.version?.number ?? "?"} — cluster "${body.cluster_name ?? "serverless"}"`));
    return true;
  } catch (e) {
    console.log(c.red(`  ✗ Elasticsearch unreachable: ${e.message}`));
    return false;
  }
}

async function checkKibana(env, kbUrl) {
  if (!kbUrl) {
    console.log(c.yellow("  ⚠ KIBANA_URL not set — case creation and Kibana links will be skipped."));
    return false;
  }
  try {
    const auth = env.KIBANA_API_KEY
      ? `ApiKey ${env.KIBANA_API_KEY}`
      : `Basic ${Buffer.from(`${env.ELASTICSEARCH_USERNAME}:${env.ELASTICSEARCH_PASSWORD}`).toString("base64")}`;
    const res = await fetch(kbUrl.replace(/\/$/, "") + "/api/status", {
      headers: { Authorization: auth, "kbn-xsrf": "true" },
    });
    if (!res.ok) {
      console.log(c.yellow(`  ⚠ Kibana responded HTTP ${res.status} — events will still be ingested.`));
      return false;
    }
    const body = await res.json();
    const v = typeof body.version === "object" ? body.version?.number : body.version;
    console.log(c.green(`  ✓ Kibana ${v ?? "?"} — "${body.name ?? "unknown"}"`));
    return true;
  } catch (e) {
    console.log(c.yellow(`  ⚠ Kibana unreachable: ${e.message} — events will still be ingested.`));
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CHILD PROCESS RUNNER — runs the ORIGINAL scripts, unmodified
// ═══════════════════════════════════════════════════════════════════════════

function run(script, args, env, cwd) {
  return new Promise((resolve) => {
    console.log(c.dim(`\n  $ node ${path.relative(ROOT, script)} ${args.join(" ")}\n`));
    // Hand stdin over to the child while it runs.
    stopReading();
    const child = spawn(process.execPath, [script, ...args], { cwd, env, stdio: "inherit" });
    const done = (code) => resolve(code);
    child.on("close", (code) => done(code ?? 1));
    child.on("error", (e) => {
      console.error(c.red(`  ✗ Failed to start ${path.basename(script)}: ${e.message}`));
      done(1);
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// STEP A — POC SIMULATOR  (simulator/demo-walkthrough.js, unchanged)
// ═══════════════════════════════════════════════════════════════════════════

// The simulator is the only part that needs an npm dependency. The demo-log
// scripts use Node built-ins only — which is why they can succeed while this
// step fails on a folder where `npm install` was never run.
function hasElasticClient() {
  try {
    require_.resolve("@elastic/elasticsearch");
    return true;
  } catch {
    return false;
  }
}

async function runSimulator(env, count) {
  console.log("\n" + c.b("── STEP: POC Simulator — sample events, attack scenarios, alerts ──"));

  if (!hasElasticClient()) {
    console.log(c.red("  ✗ Dependency @elastic/elasticsearch is not installed."));
    console.log(c.dim("    The POC Simulator needs it; the demo-log scripts do not, which is why"));
    console.log(c.dim("    that step can succeed while this one fails. Fix it with:\n"));
    console.log("      cd " + JSON.stringify(ROOT));
    console.log("      npm install\n");
    return false;
  }

  const code = await run(path.join(SIM_DIR, "demo-walkthrough.js"), ["--count", String(count)], env, SIM_DIR);
  if (code !== 0) {
    console.log(c.red(`\n  ✗ Simulator step exited with code ${code}. Common causes:`));
    console.log(c.dim("    • npm install was not run in this folder (missing @elastic/elasticsearch)"));
    console.log(c.dim("    • the API key cannot write to .alerts-security.alerts-default"));
    console.log(c.dim("      → needs 'all' privileges, or at least write on logs-* and .alerts-security.alerts-*"));
    console.log(c.dim("    • the Kibana endpoint rejected the API key (case creation)"));
    console.log(c.dim("    The error text printed just above this line is the real cause."));
  }
  return code === 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// STEP B — DEMO WALKTHROUGH LOGS
//          generate_all_demo_logs.cjs  →  ingest_all_demo_logs.cjs (unchanged)
// ═══════════════════════════════════════════════════════════════════════════

function findCombinedFiles() {
  if (!fs.existsSync(LOGS_DIR)) return [];
  return fs
    .readdirSync(LOGS_DIR)
    .filter((f) => f.startsWith("demo_logs_combined_") && f.endsWith(".ndjson"))
    .sort()
    .map((f) => path.join(LOGS_DIR, f));
}

async function runDemoLogs(env, { regenerate, yes }) {
  console.log("\n" + c.b("── STEP: Demo walkthrough logs — PA PAN-OS + Windows + Linux ──"));

  if (!env.ELASTICSEARCH_API_KEY) {
    console.log(c.red("  ✗ The demo-log ingest script supports API key auth only."));
    console.log(c.dim("    Add ELASTICSEARCH_API_KEY to your section in credentials.txt and re-run."));
    return false;
  }

  let existing = findCombinedFiles();

  let doGenerate = regenerate;
  if (doGenerate === null) {
    if (existing.length === 0) {
      console.log(c.dim("  No demo_logs_combined_*.ndjson found — generating a fresh set."));
      doGenerate = true;
    } else {
      console.log(c.dim(`  Found ${existing.length} existing log set(s); newest: ${path.basename(existing.at(-1))}`));
      doGenerate = await confirm("  Generate a fresh set with current timestamps?", yes);
    }
  }

  if (doGenerate) {
    const code = await run(path.join(LOGS_DIR, "generate_all_demo_logs.cjs"), [], env, LOGS_DIR);
    if (code !== 0) {
      console.log(c.red(`  ✗ Log generation exited with code ${code}`));
      return false;
    }
    existing = findCombinedFiles();
  }

  if (existing.length === 0) {
    console.log(c.red("  ✗ No demo_logs_combined_*.ndjson available to ingest."));
    return false;
  }

  // Pass the combined file explicitly. Do NOT let the ingest script auto-discover:
  // the folder also holds the per-category files, which would double-ingest.
  const newest = existing.at(-1);
  console.log(c.dim(`  Ingesting: ${path.basename(newest)}`));

  const code = await run(path.join(LOGS_DIR, "ingest_all_demo_logs.cjs"), [newest], env, LOGS_DIR);
  if (code !== 0) console.log(c.red(`  ✗ Demo-log ingest exited with code ${code}`));
  return code === 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════

async function runCleanup(env, yes) {
  console.log("\n" + c.b("── STEP: Cleanup ──"));
  console.log(c.yellow("  This deletes documents tagged 'elastic-security-sample-data'"));
  console.log(c.yellow("  and 'elastic-security-demo-data', plus generated sample cases."));

  if (!(await confirm("\n  Proceed with cleanup?", yes))) {
    console.log("  Aborted.");
    return false;
  }

  await run(path.join(SIM_DIR, "sample-data.js"), ["--cleanup", "--yes"], env, SIM_DIR);
  if (env.ELASTICSEARCH_API_KEY) {
    await run(path.join(LOGS_DIR, "ingest_all_demo_logs.cjs"), ["--cleanup"], env, LOGS_DIR);
  } else {
    console.log(c.yellow("  ⚠ Skipping demo-log cleanup — it requires ELASTICSEARCH_API_KEY."));
  }
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// MENUS
// ═══════════════════════════════════════════════════════════════════════════

async function chooseTarget(preset) {
  if (preset) {
    const found = Object.values(TARGETS).find((t) => t.key === preset);
    if (!found) fail(`Unknown --target "${preset}". Use: serverless | cloud_hosted | self_managed`);
    console.log(`  Destination: ${c.cyan(found.label)}  ${c.dim(`[${found.key}]`)}`);
    return found;
  }

  console.log(c.b("  Select Elasticsearch destination"));
  console.log("  " + c.dim("─".repeat(58)));
  for (const [n, t] of Object.entries(TARGETS)) console.log(`    ${c.b(n + ".")} ${t.label}`);
  console.log("  " + c.dim("─".repeat(58)));

  while (true) {
    const a = await ask("  Enter 1, 2 or 3: ");
    if (TARGETS[a]) {
      console.log(`  → ${c.cyan(TARGETS[a].label)}\n`);
      return TARGETS[a];
    }
    console.log(c.yellow("  Please enter 1, 2 or 3."));
  }
}

async function chooseTask(preset) {
  if (preset) {
    const found = Object.values(TASKS).find((t) => t.key === preset);
    if (!found) fail(`Unknown --task "${preset}". Use: simulator | demo-logs | both | cleanup`);
    return found;
  }

  console.log(c.b("  What would you like to ingest?"));
  console.log("  " + c.dim("─".repeat(58)));
  for (const [n, t] of Object.entries(TASKS)) console.log(`    ${c.b(n + ".")} ${t.label}`);
  console.log("  " + c.dim("─".repeat(58)));

  while (true) {
    const a = await ask("  Enter 1, 2, 3 or 4: ");
    if (TASKS[a]) return TASKS[a];
    console.log(c.yellow("  Please enter 1, 2, 3 or 4."));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

function parseArgs(argv) {
  const get = (name) => {
    const i = argv.indexOf(name);
    return i > -1 ? argv[i + 1] : null;
  };
  return {
    target: get("--target"),
    task: argv.includes("--cleanup") ? "cleanup" : get("--task"),
    count: parseInt(get("--count"), 10) || 50,
    regenerate: argv.includes("--regenerate") ? true : argv.includes("--no-regenerate") ? false : null,
    yes: argv.includes("--yes") || argv.includes("-y"),
    help: argv.includes("--help") || argv.includes("-h"),
  };
}

function printHelp() {
  console.log(`
  Usage: node run.js [options]

    --target <name>     serverless | cloud_hosted | self_managed
    --task <name>       simulator | demo-logs | both | cleanup
    --count <n>         events per package for the POC Simulator (default 50)
    --regenerate        always regenerate demo NDJSON before ingest
    --no-regenerate     reuse the newest existing demo NDJSON
    --cleanup           shorthand for --task cleanup
    --yes, -y           skip confirmation prompts
    --help, -h          show this help

  With no options, run.js is fully interactive.
  Credentials are read from credentials.txt (not .env).
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return printHelp();

  banner();

  // A stray .env in this folder would be picked up by the original clients and
  // could silently override the destination you chose.
  for (const dir of [ROOT, SIM_DIR, LOGS_DIR]) {
    if (fs.existsSync(path.join(dir, ".env"))) {
      console.log(c.yellow(`  ⚠ A .env file exists in ${path.relative(ROOT, dir) || "."} — it may override credentials.txt.`));
      console.log(c.dim("    Rename or delete it to guarantee the selected destination is used.\n"));
    }
  }

  const target = await chooseTarget(args.target);
  const sections = parseCredentials(CRED_FILE);
  const cfg = sections[target.key];

  if (!cfg || Object.keys(cfg).length === 0) {
    fail(`Section [${target.key}] is missing or empty in credentials.txt.`);
  }

  const { env, esUrl, kbUrl, apiKey, user } = buildEnv(target.key, cfg);

  console.log(c.b("  Connection"));
  console.log(`    Elasticsearch : ${esUrl}`);
  console.log(`    Kibana        : ${kbUrl || c.dim("(not set)")}`);
  console.log(`    Auth          : ${apiKey ? `API key ${mask(apiKey)}` : `basic auth as "${user}"`}`);
  if (env.ELASTICSEARCH_INSECURE === "true") console.log(c.yellow("    TLS           : certificate verification DISABLED"));
  console.log("");

  console.log(c.b("  Verifying..."));
  const esOk = await checkElasticsearch(env, esUrl);
  if (!esOk) fail("Cannot continue without an Elasticsearch connection.");
  await checkKibana(env, kbUrl);
  console.log("");

  const task = await chooseTask(args.task);

  if (task.key === "cleanup") {
    await runCleanup(env, args.yes);
    console.log("\n" + c.green("  Cleanup finished.") + "\n");
    return;
  }

  if (!args.yes) {
    const ok = await confirm(`\n  Run "${task.label}" against ${esUrl}?`, false);
    if (!ok) {
      console.log("  Aborted.");
      return;
    }
  }

  const results = {};
  if (task.key === "simulator" || task.key === "both") {
    results.simulator = await runSimulator(env, args.count);
  }
  if (task.key === "demo-logs" || task.key === "both") {
    results.demoLogs = await runDemoLogs(env, { regenerate: args.regenerate, yes: args.yes });
  }

  // ── Summary ──
  console.log("\n" + c.b("══════════════════════════════════════════════════════════════"));
  console.log(c.b("  SUMMARY"));
  console.log(c.b("══════════════════════════════════════════════════════════════"));
  console.log(`  Destination : ${target.label}`);
  for (const [k, v] of Object.entries(results)) {
    const name = k === "simulator" ? "POC Simulator" : "Demo walkthrough logs";
    console.log(`  ${name.padEnd(22)}: ${v ? c.green("✓ completed") : c.red("✗ failed")}`);
  }

  if (kbUrl) {
    console.log("\n  " + c.b("Explore in Kibana"));
    console.log(`    Alerts           : ${kbUrl}/app/security/alerts`);
    console.log(`    Attack Discovery : ${kbUrl}/app/security/attack_discovery`);
    console.log(`    Cases            : ${kbUrl}/app/security/cases`);
    console.log(`    Hosts            : ${kbUrl}/app/security/hosts`);
    console.log(`    Overview         : ${kbUrl}/app/security/overview`);
    console.log(`    Discover         : ${kbUrl}/app/discover`);
  }

  console.log("\n  " + c.b("Quick ES|QL checks"));
  console.log(c.dim("    FROM logs-panw.panos-default | STATS c=COUNT(*) BY panw.panos.type | SORT c DESC"));
  console.log(c.dim("    FROM logs-windows.security-default | STATS c=COUNT(*) BY winlog.event_id | SORT c DESC"));
  console.log(c.dim("    FROM logs-system.auth-default | STATS c=COUNT(*) BY event.action | SORT c DESC"));
  console.log("\n  To remove everything later:  " + c.cyan("node run.js --cleanup") + "\n");
}

main()
  .catch((e) => {
    console.error("\n" + c.red("✗ " + (e.stack || e.message || e)) + "\n");
    process.exitCode = 1;
  })
  .finally(closeReadline);
