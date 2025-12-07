const fs = require("fs");
const path = require("path");
const axios = require("axios");

const ROOT = path.resolve(__dirname, "..");
const baseDir = path.join(ROOT, "downloaded_packages");
const outDir = path.join(ROOT, "results_obfuscation/v2_raw");
const CONCURRENCY = 5;

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

// use folder names under downloaded_packages as targets
const pkgs = fs
  .readdirSync(baseDir)
  .filter((name) => fs.statSync(path.join(baseDir, name)).isDirectory());

let idx = 0;

async function scanOne(folderName) {
  const safe = folderName; // folder name is already "safe"
  const target = path.join(baseDir, safe, "package");
  const outPath = path.join(outDir, `${safe}.json`);
  const errPath = path.join(outDir, `${safe}.error.json`);

  if (!fs.existsSync(target)) {
    fs.writeFileSync(
      errPath,
      JSON.stringify(
        { folder: safe, error: "target not found", target },
        null,
        2
      )
    );
    console.warn("target not found", safe);
    return;
  }

  try {
    const url = `http://localhost:3050/scan/obfuscation?dir=${encodeURIComponent(
      target
    )}`;
    const resp = await axios.get(url, { timeout: 300000 });
    fs.writeFileSync(outPath, JSON.stringify(resp.data, null, 2));
    console.log("scanned", safe);
  } catch (e) {
    fs.writeFileSync(
      errPath,
      JSON.stringify({ folder: safe, error: e.message }, null, 2)
    );
    console.error("failed", safe, e.message);
  }
}

async function worker() {
  for (;;) {
    let name;
    if (idx < pkgs.length) {
      name = pkgs[idx++];
    } else {
      break;
    }

    await scanOne(name);
    await new Promise((r) => setTimeout(r, 100));
  }
}

(async () => {
  const workers = new Array(CONCURRENCY).fill(0).map(() => worker());
  await Promise.all(workers);
  console.log("All done. Results in", outDir);
})();
