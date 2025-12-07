// Count success, errors, empty results, and obfuscation flags in the scan outputs.

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const dir = path.join(ROOT, "results_obfuscation/v2_raw");

const files = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith(".json") && !f.endsWith(".error.json"));

let total = 0;
let ok = 0;
let errors = 0;
let obfuscated = 0;
let noResults = 0;

for (const f of files) {
  total++;
  const data = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));

  if (!data.results) {
    errors++;
    continue;
  }

  if (data.results.length === 0) {
    noResults++;
    continue;
  }

  const hasErr = data.results.some((r) => r.error);
  const hasObf = data.results.some((r) => r.obfuscated === true);

  if (hasErr) {
    errors++;
  } else {
    ok++;
  }

  if (hasObf) {
    obfuscated++;
  }
}

console.log({ total, ok, errors, noResults, obfuscated });
