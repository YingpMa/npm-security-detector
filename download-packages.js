const fs = require("fs");
const fsp = require("fs").promises;
const path = require("path");
const https = require("https");
const { exec } = require("child_process");
const util = require("util");
const execAsync = util.promisify(exec);

const inputFile = process.argv[2];
const outDir = process.argv[3] || "downloaded_packages";
const cutoffDate = new Date(process.argv[4] || "2025-08-01");
const CONCURRENCY = parseInt(process.argv[5] || "5", 10);

if (!inputFile) {
  console.error(
    "Usage: node download-packages.js <packages.txt> [outDir] [cutoffDate] [concurrency]"
  );
  process.exit(1);
}

if (!fs.existsSync(inputFile)) {
  console.error("Input file not found:", inputFile);
  process.exit(1);
}

if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

const lines = fs
  .readFileSync(inputFile, "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter(Boolean);

// safe name for filesystem (scoped packages: @scope/name -> @scope+name)
function safeName(pkg) {
  return pkg.replace(/\//g, "+");
}

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "npm-downloader/1.0" } }, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(
              new Error(
                `Invalid JSON from ${url}: ${e.message} - raw: ${data.slice(
                  0,
                  200
                )}`
              )
            );
          }
        });
      })
      .on("error", reject);
  });
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", (err) => {
        try {
          fs.unlinkSync(dest);
        } catch (_) {}
        reject(err);
      });
  });
}

async function processPackage(pkgName) {
  const logPrefix = `[${pkgName}]`;
  try {
    const metaUrl = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
    const meta = await fetchJSON(metaUrl);

    // Build list of versions with times
    const timeMap = meta.time || {};
    const versionEntries = Object.entries(timeMap)
      .filter(([ver]) => ver !== "created" && ver !== "modified")
      .map(([ver, t]) => ({ ver, time: new Date(t) }))
      .filter(({ time }) => time <= cutoffDate);

    if (versionEntries.length === 0) {
      throw new Error("NO_VERSION_BEFORE_CUTOFF");
    }

    // pick the latest version before cutoff
    versionEntries.sort((a, b) => a.time - b.time);
    const selected = versionEntries[versionEntries.length - 1].ver;
    const selectedMeta = meta.versions && meta.versions[selected];
    if (!selectedMeta || !selectedMeta.dist || !selectedMeta.dist.tarball) {
      throw new Error("NO_TARBALL_FOR_SELECTED_VERSION");
    }
    const tarballUrl = selectedMeta.dist.tarball;

    const pkgOutBase = path.join(outDir, safeName(pkgName));
    await fsp.mkdir(pkgOutBase, { recursive: true });
    const tgzPath = path.join(
      pkgOutBase,
      `${safeName(pkgName)}-${selected}.tgz`
    );

    // download with retries
    const MAX_DL_TRIES = 3;
    let dlOk = false;
    for (let attempt = 1; attempt <= MAX_DL_TRIES; attempt++) {
      try {
        await downloadFile(tarballUrl, tgzPath);
        dlOk = true;
        break;
      } catch (e) {
        if (attempt < MAX_DL_TRIES) {
          await new Promise((r) => setTimeout(r, 1000 * attempt)); // backoff
        } else {
          throw new Error(`DOWNLOAD_FAILED: ${e.message}`);
        }
      }
    }

    // extract
    try {
      // extract into pkgOutBase (tarball structure -> package/...)
      await execAsync(`tar -xzf "${tgzPath}" -C "${pkgOutBase}"`);
    } catch (e) {
      throw new Error(`EXTRACT_FAILED: ${e.message}`);
    }

    // success object
    return { ok: true, pkg: pkgName, version: selected, dir: pkgOutBase };
  } catch (err) {
    return { ok: false, pkg: pkgName, error: err.message || String(err) };
  }
}

// simple concurrency queue
async function runQueue(items, worker, concurrency) {
  const results = [];
  let idx = 0;
  const active = [];

  function enqueueNext() {
    if (idx >= items.length) return null;
    const item = items[idx++];
    const p = (async () => {
      try {
        return await worker(item);
      } catch (e) {
        return { ok: false, pkg: item, error: e.message || String(e) };
      }
    })();
    active.push(p);
    p.finally(() => {
      const i = active.indexOf(p);
      if (i >= 0) active.splice(i, 1);
    });
    return p;
  }

  // kick off initial
  for (let i = 0; i < Math.min(concurrency, items.length); i++) enqueueNext();

  while (idx < items.length || active.length > 0) {
    // wait for any to finish
    if (active.length === 0) break;
    try {
      const r = await Promise.race(active);
      results.push(r);
      // enqueue another
      enqueueNext();
    } catch (e) {
      // race can throw if worker throws; worker catches though
      results.push({
        ok: false,
        pkg: "unknown",
        error: e.message || String(e),
      });
      enqueueNext();
    }
  }

  // Wait remaining active
  const remaining = await Promise.allSettled(active);
  for (const s of remaining) {
    if (s.status === "fulfilled") results.push(s.value);
    else
      results.push({
        ok: false,
        pkg: "unknown",
        error: s.reason?.message || String(s.reason),
      });
  }

  return results;
}

// run
(async () => {
  console.log(
    `Starting download for ${
      lines.length
    } packages (concurrency=${CONCURRENCY}), cutoff=${
      cutoffDate.toISOString().split("T")[0]
    }`
  );
  const results = await runQueue(lines, processPackage, CONCURRENCY);

  const success = results.filter((r) => r.ok);
  const failed = results.filter((r) => !r.ok);

  // write logs
  const successPath = path.join(outDir, "success_packages.txt");
  const failedPath = path.join(outDir, "failed_packages.txt");

  await fsp.writeFile(
    successPath,
    success.map((s) => `${s.pkg}@${s.version}    ${s.dir || ""}`).join("\n"),
    "utf8"
  );
  await fsp.writeFile(
    failedPath,
    failed.map((f) => `${f.pkg}\t${f.error}`).join("\n"),
    "utf8"
  );

  console.log(`Done. success: ${success.length}, failed: ${failed.length}`);
  console.log(`Logs: ${successPath}, ${failedPath}`);
})();
