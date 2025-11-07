// filter_before_cutoff.js
// node filter_before_cutoff.js all_top10000.txt 2025-08-01 filtered_packages.txt
const fs = require("fs");
const https = require("https");

const input = process.argv[2];
const cutoff = new Date(process.argv[3] || "2025-08-01");
const output = process.argv[4] || "filtered_packages.txt";

if (!input) {
  console.error(
    "Usage: node filter_before_cutoff.js <input> [cutoff_date] [output]"
  );
  process.exit(1);
}

const all = fs
  .readFileSync(input, "utf8")
  .split("\n")
  .map((s) => s.trim())
  .filter(Boolean);

console.log(
  `Checking ${all.length} packages (cutoff ${
    cutoff.toISOString().split("T")[0]
  })...`
);

const results = [];
let processed = 0;

(async () => {
  for (const name of all) {
    try {
      const meta = await fetchJSON(
        `https://registry.npmjs.org/${encodeURIComponent(name)}`
      );
      const created = meta.time?.created ? new Date(meta.time.created) : null;
      const before = created && created <= cutoff;
      if (before) results.push(name);
    } catch (e) {
      console.warn("⚠️", name, e.message);
    }
    processed++;
    if (processed % 100 === 0)
      console.log(`Progress: ${processed}/${all.length}`);
    await new Promise((r) => setTimeout(r, 100)); // polite delay
  }
  fs.writeFileSync(output, results.join("\n"), "utf8");
  console.log(
    `✅ ${results.length} packages existed before cutoff, saved to ${output}`
  );
})();

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on("error", reject);
  });
}
