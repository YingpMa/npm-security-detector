const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "c2_results");
if (!fs.existsSync(dir)) {
  console.error("c2_results directory not found");
  process.exit(1);
}

const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
let total = 0;
let withDns = 0;
let withFlagged = 0;

for (const f of files) {
  total++;
  const data = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  const domains = Array.isArray(data.domains) ? data.domains : [];
  if (domains.length > 0) withDns++;

  let flaggedHere = 0;
  const vt = data.vt || {};
  for (const d of domains) {
    const r = vt[d];
    const stats = r?.data?.attributes?.last_analysis_stats;
    if (stats) {
      const positives = (stats.malicious || 0) + (stats.suspicious || 0);
      if (positives > 0) flaggedHere++;
    }
  }
  if (flaggedHere > 0) withFlagged++;
}

console.log("---- C2 scan summary ----");
console.log(`Total C2 result files: ${total}`);
console.log(`Packages with any DNS/TLS event: ${withDns}`);
console.log(`Packages with VT-flagged domains: ${withFlagged}`);
console.log("(Note: if VT was not configured, flagged will be 0)");
