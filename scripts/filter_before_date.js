// Filters npm package names by creation date.
// Keeps only packages published before the specified date and writes the result to a file.

const fs = require("fs");
const https = require("https");

const inputFile = process.argv[2];
const cutoffDate = new Date(process.argv[3] || "2025-08-01");
const outputFile = process.argv[4] || "filtered_packages.txt";

if (!inputFile) {
  console.error("Missing input file.\nExample:");
  console.error("  node filter_before_cutoff.js all.txt 2025-08-01 out.txt");
  process.exit(1);
}

const pkgList = fs
  .readFileSync(inputFile, "utf8")
  .split("\n")
  .map((x) => x.trim())
  .filter(Boolean);

console.log(
  `Total packages: ${pkgList.length} (cutoff: ${
    cutoffDate.toISOString().split("T")[0]
  })`
);

const selected = [];
let count = 0;

(async () => {
  for (const pkg of pkgList) {
    try {
      const meta = await getJSON(
        `https://registry.npmjs.org/${encodeURIComponent(pkg)}`
      );

      const createdAt = meta?.time?.created
        ? new Date(meta.time.created)
        : null;

      if (createdAt && createdAt <= cutoffDate) {
        selected.push(pkg);
      }
    } catch (err) {
      console.warn("Fetch failed:", pkg, "-", err.message);
    }

    count++;
    if (count % 100 === 0) {
      console.log(`Processed ${count}/${pkgList.length}`);
    }

    // avoid sending too many requests too fast
    await delay(100);
  }

  fs.writeFileSync(outputFile, selected.join("\n"), "utf8");
  console.log(
    `Done. ${selected.length} packages created before cutoff. Saved to ${outputFile}`
  );
})();

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on("error", reject);
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
