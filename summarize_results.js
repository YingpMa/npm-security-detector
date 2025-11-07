const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "results");
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));

let total = 0,
  ok = 0,
  errors = 0,
  obfuscated = 0;
for (const f of files) {
  total++;
  const data = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  if (!data.results || data.results.length === 0) {
    errors++;
    continue;
  }
  const hasErr = data.results.some((r) => r.error);
  const hasObf = data.results.some((r) => r.obfuscated === true);
  if (hasErr) errors++;
  if (hasObf) obfuscated++;
  if (!hasErr) ok++;
}
console.log({ total, ok, errors, obfuscated });
