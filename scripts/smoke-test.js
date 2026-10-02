#!/usr/bin/env node
/**
 * Offline smoke test — no Elasticsearch needed.
 *   1. Syntax-checks every script.
 *   2. Runs the demo-log generator into a temp folder.
 *   3. Asserts every event is tagged, routable, and uses the shared entity model.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
const ok = (m) => console.log(`  ✓ ${m}`);
const bad = (m) => { console.error(`  ✗ ${m}`); failures++; };

console.log("Syntax");
for (const f of [
  "run.js", "simulator/demo-walkthrough.js", "simulator/sample-data.js",
  "simulator/es-client.js", "simulator/kibana-client.js",
  "demo-logs/generate_all_demo_logs.cjs", "demo-logs/ingest_all_demo_logs.cjs",
]) {
  try { execFileSync(process.execPath, ["--check", path.join(ROOT, f)], { stdio: "pipe" }); ok(f); }
  catch (e) { bad(`${f}: ${e.stderr?.toString().split("\n")[0]}`); }
}

console.log("\nGenerator");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aisoc-"));
fs.copyFileSync(path.join(ROOT, "demo-logs/generate_all_demo_logs.cjs"), path.join(tmp, "gen.cjs"));
execFileSync(process.execPath, [path.join(tmp, "gen.cjs")], { stdio: "pipe" });
const combined = fs.readdirSync(tmp).find((f) => f.startsWith("demo_logs_combined_"));
if (!combined) { bad("no combined NDJSON written"); process.exit(1); }
const docs = fs.readFileSync(path.join(tmp, combined), "utf8").trim().split("\n").map((l) => JSON.parse(l));
docs.length > 5000 ? ok(`${docs.length} events generated`) : bad(`only ${docs.length} events`);

const untagged = docs.filter((d) => !(d.tags || []).includes("elastic-security-demo-data")).length;
untagged === 0 ? ok("every event tagged elastic-security-demo-data") : bad(`${untagged} untagged events`);

const unroutable = docs.filter((d) => !d.data_stream?.dataset).length;
unroutable === 0 ? ok("every event has data_stream.dataset") : bad(`${unroutable} events without data_stream.dataset`);

const users = new Set(docs.map((d) => d.user?.name));
for (const u of ["rjohnson", "kpatel", "admin.ops"]) users.has(u) ? ok(`story user present: ${u}`) : bad(`missing user ${u}`);
const hosts = new Set(docs.map((d) => d.host?.name));
for (const h of ["SRV-DC01", "SRV-FILE01", "SRV-LINUX01"]) hosts.has(h) ? ok(`story host present: ${h}`) : bad(`missing host ${h}`);

console.log("\nSimulator entity alignment");
const sim = fs.readFileSync(path.join(ROOT, "simulator/sample-data.js"), "utf8");
const legacy = ["web-prod-01", "db-prod-02", "app-staging-03", "compromised-dev", "198.51.100.77"];
const leftovers = legacy.filter((s) => sim.includes(`"${s}"`));
leftovers.length === 0 ? ok("no legacy upstream entities remain") : bad(`legacy entities found: ${leftovers.join(", ")}`);

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failures ? `\n${failures} check(s) failed` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
