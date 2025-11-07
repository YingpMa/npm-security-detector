const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

if (process.argv.length < 4) {
  console.error(
    "Usage: node dynamic_c2_scan_docker.js <packages_file> <out_dir> [cap_seconds]"
  );
  process.exit(1);
}

const pkgsFile = process.argv[2];
const outDir = process.argv[3];
const CAP = Number(process.argv[4] || process.env.CAP_DURATION || 40);

if (!fs.existsSync(pkgsFile)) {
  console.error("packages file not found:", pkgsFile);
  process.exit(1);
}
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

function safeName(name) {
  return name.replace(/\//g, "+");
}

const pkgs = fs
  .readFileSync(pkgsFile, "utf8")
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter(Boolean);

console.log(
  `Starting dynamic C2 Docker scan: ${pkgs.length} packages, cap=${CAP}s, outDir=${outDir}`
);

for (let i = 0; i < pkgs.length; i++) {
  const pkg = pkgs[i];
  const safe = safeName(pkg);
  const base = path.join(outDir, safe);

  const outPcap = `${base}.pcap`;
  const outTxt = `${base}.txt`;
  const outJson = `${base}.json`;
  const outStart = `${base}.start.txt`;
  const outEnd = `${base}.end.txt`;

  if (fs.existsSync(outJson)) {
    console.log(`[${i + 1}/${pkgs.length}] SKIP existing: ${pkg}`);
    continue;
  }

  console.log(`\n[${i + 1}/${pkgs.length}] RUN: ${pkg}`);
  const scriptInsideContainer = `
set -e
apt-get update -qq || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark dnsutils >/dev/null 2>&1 || true
mkdir -p /work && cd /work
date -Iseconds > /out/${safe}.start.txt
tshark -i any -a duration:${CAP} -w /out/${safe}.pcap 2>/dev/null &
TSHARK_PID=$!
sleep 1

# --- manually import ---
nslookup github.com >/dev/null 2>&1 || true
nslookup www.npmjs.com >/dev/null 2>&1 || true
# ---------------------------------------

npm init -y >/dev/null 2>&1 || true
npm i ${pkg} --no-audit --no-fund >/dev/null 2>&1 || true
wait $TSHARK_PID || true
date -Iseconds > /out/${safe}.end.txt
tshark -r /out/${safe}.pcap -Y 'dns or tls.handshake.extensions_server_name' -T fields -e dns.qry.name -e tls.handshake.extensions_server_name > /out/${safe}.txt 2>/dev/null || true
`;

  const dockerArgs = [
    "run",
    "--rm",
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW",
    "-v",
    `${path.resolve(outDir)}:/out`,
    "node:18",
    "bash",
    "-lc",
    scriptInsideContainer,
  ];

  const r = spawnSync("docker", dockerArgs, { stdio: "inherit" });
  if (r.error) {
    console.error(`docker run failed for ${pkg}: ${r.error.message}`);
  }

  let domains = [];
  if (fs.existsSync(outTxt)) {
    const lines = fs.readFileSync(outTxt, "utf8").split(/\r?\n/);
    const seen = new Set();
    for (const line of lines) {
      if (!line.trim()) continue;
      const parts = line
        .split("\t")
        .map((x) => x.trim())
        .filter(Boolean);
      const name = parts[0] || parts[1];
      if (name && !seen.has(name)) {
        seen.add(name);
        domains.push(name);
      }
    }
  }

  const record = {
    pkg,
    domains,
    vt: {},
    timestamp: new Date().toISOString(),
  };
  fs.writeFileSync(outJson, JSON.stringify(record, null, 2), "utf8");
  console.log(`WROTE: ${path.basename(outJson)} (domains: ${domains.length})`);

  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
}

console.log("\nDone.");
