#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════
 *  Elastic Security Demo — Unified Log Ingest Script
 * ══════════════════════════════════════════════════════════════════
 *
 *  Ingests ALL demo logs (PA, Windows, Linux) into the correct
 *  Elastic data streams with proper pipeline routing.
 *
 *  Usage:
 *    node ingest_all_demo_logs.js                           # auto-discover demo_logs_*.ndjson
 *    node ingest_all_demo_logs.js demo_logs_combined_*.ndjson  # specific file
 *    node ingest_all_demo_logs.js --cleanup                 # remove all demo data
 *
 *  Prerequisites:
 *    - Node.js 18+
 *    - NDJSON files from generate_all_demo_logs.js
 *    - ELASTICSEARCH_URL / ELASTICSEARCH_CLOUD_ID and ELASTICSEARCH_API_KEY env vars
 *      (run.js sets these from credentials.txt)
 *
 * ══════════════════════════════════════════════════════════════════
 */

const https = require("https");
const http  = require("http");
const fs    = require("fs");
const path  = require("path");

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION — edit these or set environment variables
// ═══════════════════════════════════════════════════════════════

// Option A: Cloud ID (recommended for Elastic Cloud)
const CLOUD_ID = process.env.ELASTICSEARCH_CLOUD_ID || "";

// Option B: Direct URL (for self-managed or Serverless)
const DIRECT_URL = process.env.ELASTICSEARCH_URL || "";

const API_KEY = process.env.ELASTICSEARCH_API_KEY || "";
// No credentials are hard-coded. run.js supplies these from credentials.txt.

const BATCH_SIZE = 500;
const DEMO_TAG   = "elastic-security-demo-data";

// ═══════════════════════════════════════════════════════════════
// DATA STREAM ROUTING
//
// Each log category maps to a target data stream.
// The Elastic integration ingest pipelines are NOT used here
// because our data is already ECS-mapped (pre-parsed).
// We bypass default pipelines with pipeline=_none per-doc.
// ═══════════════════════════════════════════════════════════════

const ROUTING = {
  // PA PAN-OS — all types go to the same data stream
  "panw.panos":                    { target: "logs-panw.panos-default" },

  // Windows Security (Winlogbeat / Elastic Agent)
  "windows.security":              { target: "logs-windows.security-default" },

  // Windows Sysmon
  "windows.sysmon_operational":    { target: "logs-windows.sysmon_operational-default" },

  // Linux system auth
  "system.auth":                   { target: "logs-system.auth-default" },

  // Elastic Defend (endpoint) — only for reference; real EDR data
  // comes from the agent, not from this script
  "endpoint.events.process":       { target: "logs-endpoint.events.process-default" },
  "endpoint.events.network":       { target: "logs-endpoint.events.network-default" },
  "endpoint.events.file":          { target: "logs-endpoint.events.file-default" },
};

// ═══════════════════════════════════════════════════════════════
// CLOUD ID DECODER
// ═══════════════════════════════════════════════════════════════
function decodeCloudId(cloudId) {
  const b64 = cloudId.split(":")[1];
  const decoded = Buffer.from(b64, "base64").toString("utf8");
  const parts = decoded.split("$");
  return `https://${parts[1]}.${parts[0]}`;
}

function getESUrl() {
  if (DIRECT_URL) return DIRECT_URL;
  if (CLOUD_ID) return decodeCloudId(CLOUD_ID);
  console.error("✗ No Elasticsearch URL. Set ELASTICSEARCH_CLOUD_ID or ELASTICSEARCH_URL.");
  process.exit(1);
}

const ES_URL = getESUrl();

// ═══════════════════════════════════════════════════════════════
// HTTP HELPER
// ═══════════════════════════════════════════════════════════════
function request(method, urlStr, body, contentType = "application/json") {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const lib = url.protocol === "https:" ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 9200),
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": contentType,
        "Authorization": `ApiKey ${API_KEY}`,
      },
    };
    if (body) options.headers["Content-Length"] = Buffer.byteLength(body);

    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════
// VERIFY CONNECTION
// ═══════════════════════════════════════════════════════════════
async function verifyConnection() {
  try {
    const res = await request("GET", ES_URL + "/");
    if (res.status === 200) {
      console.log(`✓ Connected to Elasticsearch ${res.body.version?.number} (${res.body.cluster_name})`);
      return true;
    }
    console.error(`✗ HTTP ${res.status}:`, JSON.stringify(res.body).slice(0, 300));
    return false;
  } catch (e) {
    console.error(`✗ Connection error: ${e.message}`);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// ENSURE DATA STREAM EXISTS
// ═══════════════════════════════════════════════════════════════
const checkedStreams = new Set();
async function ensureDataStream(target) {
  if (checkedStreams.has(target)) return;
  checkedStreams.add(target);

  const res = await request("GET", `${ES_URL}/_data_stream/${target}`);
  if (res.status === 200) {
    console.log(`  ✓ Data stream exists: ${target}`);
  } else {
    // Try to create it — some custom data streams may need this
    console.log(`  ⚠ Data stream ${target} not found (${res.status}). Will attempt to index directly.`);
    console.log(`    Tip: Install the corresponding Elastic integration first (e.g., Palo Alto, Windows, System).`);
  }
}

// ═══════════════════════════════════════════════════════════════
// RESOLVE TARGET DATA STREAM FOR A DOCUMENT
// ═══════════════════════════════════════════════════════════════
function resolveTarget(doc) {
  const dataset = doc.data_stream?.dataset || "";
  const route = ROUTING[dataset];
  if (route) return route.target;

  // Fallback: construct from data_stream fields
  if (doc.data_stream?.type && doc.data_stream?.dataset) {
    return `${doc.data_stream.type}-${doc.data_stream.dataset}-${doc.data_stream.namespace || "default"}`;
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════
// BULK INGEST
// ═══════════════════════════════════════════════════════════════
async function bulkIngest(docs) {
  const lines = [];
  for (const doc of docs) {
    const target = resolveTarget(doc);
    if (!target) {
      console.warn(`  ⚠ Could not resolve target for doc with dataset: ${doc.data_stream?.dataset}`);
      continue;
    }
    // Use "create" action. pipeline=_none at URL level prevents default ingest pipeline
    // from re-processing our already-ECS-mapped data.
    lines.push(JSON.stringify({ create: { _index: target } }));
    lines.push(JSON.stringify(doc));
  }

  if (lines.length === 0) return { total: 0, failed: [] };

  const body = lines.join("\n") + "\n";
  const res = await request("POST", `${ES_URL}/_bulk?pipeline=_none`, body, "application/x-ndjson");

  if (res.status >= 400) {
    throw new Error(`Bulk failed (HTTP ${res.status}): ${JSON.stringify(res.body).slice(0, 400)}`);
  }

  const items = res.body.items || [];
  const failed = items.filter(i => (i.create || i.index)?.error);
  return { total: items.length, failed };
}

// ═══════════════════════════════════════════════════════════════
// FILE DISCOVERY
// ═══════════════════════════════════════════════════════════════
function discoverFiles() {
  const explicit = process.argv.slice(2).filter(a => !a.startsWith("--"));
  if (explicit.length > 0) {
    return explicit.map(f => {
      const abs = path.resolve(f);
      if (!fs.existsSync(abs)) { console.error(`✗ File not found: ${abs}`); process.exit(1); }
      return abs;
    });
  }

  // Auto-discover demo_logs_*.ndjson in the script directory
  const dir = __dirname;
  const files = fs.readdirSync(dir)
    .filter(f => f.startsWith("demo_logs_") && f.endsWith(".ndjson"))
    .sort()
    .map(f => path.join(dir, f));

  if (files.length === 0) {
    console.error("✗ No demo_logs_*.ndjson files found in: " + dir);
    console.error("  Run generate_all_demo_logs.js first.");
    process.exit(1);
  }
  return files;
}

// ═══════════════════════════════════════════════════════════════
// CLEANUP — remove all demo data
// ═══════════════════════════════════════════════════════════════
async function cleanup() {
  console.log("\n⚠ Cleanup: removing all documents tagged with:", DEMO_TAG);

  const targets = [...new Set(Object.values(ROUTING).map(r => r.target))];

  for (const target of targets) {
    process.stdout.write(`  Cleaning ${target}...`);
    try {
      const res = await request("POST", `${ES_URL}/${target}/_delete_by_query?conflicts=proceed`, JSON.stringify({
        query: { term: { "tags": DEMO_TAG } }
      }));
      if (res.status < 300) {
        const deleted = res.body.deleted || 0;
        console.log(` deleted ${deleted} docs`);
      } else {
        console.log(` skipped (${res.status})`);
      }
    } catch (e) {
      console.log(` error: ${e.message}`);
    }
  }

  console.log("\n✓ Cleanup complete.\n");
}

// ═══════════════════════════════════════════════════════════════
// INGEST A SINGLE FILE
// ═══════════════════════════════════════════════════════════════
async function ingestFile(filePath) {
  const fileName = path.basename(filePath);
  console.log(`\n┌─ File: ${fileName}`);

  const raw = fs.readFileSync(filePath, "utf8").split("\n").filter(l => l.trim());
  const docs = raw.map(l => JSON.parse(l));

  // Group by target data stream
  const byTarget = {};
  for (const doc of docs) {
    const target = resolveTarget(doc) || "UNKNOWN";
    if (!byTarget[target]) byTarget[target] = [];
    byTarget[target].push(doc);
  }

  console.log(`│  ${docs.length} docs — ` +
    Object.entries(byTarget).map(([t, d]) => `${t.replace("logs-", "")}: ${d.length}`).join(", "));

  // Ensure data streams exist
  for (const target of Object.keys(byTarget)) {
    if (target !== "UNKNOWN") await ensureDataStream(target);
  }

  let fileIngested = 0, fileFailed = 0;

  // Ingest per target in batches
  for (const [target, targetDocs] of Object.entries(byTarget)) {
    if (target === "UNKNOWN") {
      console.log(`│  ⚠ Skipping ${targetDocs.length} docs with unknown target`);
      continue;
    }

    const batches = Math.ceil(targetDocs.length / BATCH_SIZE);
    for (let b = 0; b < batches; b++) {
      const batch = targetDocs.slice(b * BATCH_SIZE, (b + 1) * BATCH_SIZE);
      const shortTarget = target.replace("logs-", "");
      process.stdout.write(`│  ${shortTarget} batch ${b + 1}/${batches} (${batch.length} docs)...`);

      try {
        const result = await bulkIngest(batch);
        const failCount = result.failed.length;
        fileIngested += batch.length - failCount;
        fileFailed += failCount;

        if (failCount > 0) {
          process.stdout.write(` ⚠ ${failCount} failed\n`);
          const firstErr = (result.failed[0].create || result.failed[0].index)?.error;
          if (firstErr) console.error(`│    → ${firstErr.type}: ${(firstErr.reason || "").slice(0, 200)}`);
        } else {
          process.stdout.write(` ✓\n`);
        }
      } catch (e) {
        console.error(`\n│  ✗ Error: ${e.message}`);
        fileFailed += batch.length;
      }
    }
  }

  console.log(`└─ ✓ ${fileIngested} ingested${fileFailed ? `, ✗ ${fileFailed} failed` : ""}`);
  return { ingested: fileIngested, failed: fileFailed };
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════
async function main() {
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  Elastic Security Demo — Unified Log Ingest                ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");
  console.log(`  ES URL  : ${ES_URL}`);
  console.log(`  Tag     : ${DEMO_TAG}`);

  // Handle --cleanup
  if (process.argv.includes("--cleanup")) {
    const ok = await verifyConnection();
    if (!ok) process.exit(1);
    await cleanup();
    return;
  }

  // Discover files
  const files = discoverFiles();
  console.log(`  Files   : ${files.length} file(s) found`);
  files.forEach(f => console.log(`    • ${path.basename(f)}`));

  // Verify connection
  const ok = await verifyConnection();
  if (!ok) process.exit(1);

  // Check routing targets
  console.log("\nData stream routing:");
  for (const [dataset, route] of Object.entries(ROUTING)) {
    console.log(`  ${dataset.padEnd(35)} → ${route.target}`);
  }

  // Ingest all files
  let grandTotal = 0, grandFailed = 0;
  for (const filePath of files) {
    const { ingested, failed } = await ingestFile(filePath);
    grandTotal += ingested;
    grandFailed += failed;
  }

  // Summary
  console.log("\n══════════════════════════════════════════════════════════════");
  console.log("  INGEST COMPLETE");
  console.log("══════════════════════════════════════════════════════════════");
  console.log(`  Files processed : ${files.length}`);
  console.log(`  ✓ Total ingested: ${grandTotal}`);
  if (grandFailed > 0) console.log(`  ✗ Total failed  : ${grandFailed}`);
  console.log("\nVerify in Kibana:");
  console.log("  1. Security → Alerts     (for threat detections)");
  console.log("  2. Discover              (select each data view)");
  console.log("  3. Timeline              (correlate events)");
  console.log("\nES|QL quick checks:");
  console.log("  FROM logs-panw.panos-default   | STATS count=COUNT(*) BY panw.panos.type | SORT count DESC");
  console.log("  FROM logs-windows.security-default | STATS count=COUNT(*) BY winlog.event_id | SORT count DESC");
  console.log("  FROM logs-system.auth-default  | STATS count=COUNT(*) BY event.action | SORT count DESC");
  console.log("\nTo remove all demo data:");
  console.log("  node ingest_all_demo_logs.js --cleanup");
  console.log("══════════════════════════════════════════════════════════════\n");
}

main().catch(e => { console.error(e); process.exit(1); });
