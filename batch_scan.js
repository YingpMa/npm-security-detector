const fs = require("fs");
const path = require("path");
const axios = require("axios");

const ROOT = path.resolve(__dirname);
const baseDir = path.join(ROOT, "downloaded_packages");
const outDir = path.join(ROOT, "results");
const pkgFile = path.join(ROOT, "packages.txt");
const CONCURRENCY = 5;

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);
const pkgs = fs
  .readFileSync(pkgFile, "utf8")
  .split(/\r?\n/)
  .map((s) => s.trim())
  .filter(Boolean);

let idx = 0;
let active = 0;

async function scanOne(pkg) {
  const safe = pkg.replace(/\//g, "+");
  const target = path.join(baseDir, safe, "package");
  const outPath = path.join(outDir, `${safe}.json`);
  const errPath = path.join(outDir, `${safe}.error.json`);

  if (!fs.existsSync(target)) {
    fs.writeFileSync(
      errPath,
      JSON.stringify({ pkg, error: "target not found", target }, null, 2)
    );
    console.warn("target not found", pkg);
    return;
  }

  try {
    const url = `http://localhost:3050/scan/obfuscation?dir=${encodeURIComponent(
      target
    )}`;
    const resp = await axios.get(url, { timeout: 300000 });
    fs.writeFileSync(outPath, JSON.stringify(resp.data, null, 2));
    console.log("scanned", pkg);
  } catch (e) {
    fs.writeFileSync(
      errPath,
      JSON.stringify({ pkg, error: e.message }, null, 2)
    );
    console.error("failed", pkg, e.message);
  }
}

async function worker() {
  while (true) {
    let pkg;
    // atomic get next
    if (idx < pkgs.length) {
      pkg = pkgs[idx++];
    } else break;

    await scanOne(pkg);
    // tiny backoff
    await new Promise((r) => setTimeout(r, 100));
  }
}

(async () => {
  const workers = new Array(CONCURRENCY).fill(0).map(() => worker());
  await Promise.all(workers);
  console.log("All done. Results in", outDir);
})();
