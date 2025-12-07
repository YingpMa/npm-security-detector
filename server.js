require("dotenv").config();

const fs = require("fs").promises;
const fsSync = require("fs");
const path = require("path");
const express = require("express");
const axios = require("axios");
const { exec } = require("child_process");
const util = require("util");
const { MongoClient } = require("mongodb");

const execAsync = util.promisify(exec);

const app = express();
const PORT = 3050;

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const mongoUrl = "mongodb://localhost:27017";
const dbName = "supplyChainSecurity";
let db;

MongoClient.connect(mongoUrl, { useUnifiedTopology: true })
  .then((client) => {
    db = client.db(dbName);
    console.log("Connected to MongoDB successfully");
  })
  .catch((err) => console.error("MongoDB connection error:", err));

async function saveScanResult(type, data) {
  if (!db) return;
  const collection = db.collection("scanResults");
  const doc = { type, data, timestamp: new Date() };
  try {
    await collection.insertOne(doc);
    console.log(`Scan result of type ${type} saved successfully`);
  } catch (err) {
    console.error("Error saving scan result:", err);
  }
}

function isObfuscated(code) {
  const lines = code.split("\n");

  if (lines.length === 1 && code.length > 1000) return true;

  const avg = code.length / lines.length;
  if (avg > 200) return true;

  return false;
}

async function collectJsFiles(
  root,
  maxFiles = 200,
  maxDepth = 4,
  curDepth = 0,
  acc = []
) {
  if (curDepth > maxDepth || acc.length >= maxFiles) return acc;

  const entries = await fs.readdir(root, { withFileTypes: true });

  for (const e of entries) {
    if (acc.length >= maxFiles) break;
    const full = path.join(root, e.name);

    if (e.isDirectory()) {
      // skip common build / output folders
      if (
        e.name === "node_modules" ||
        e.name === "dist" ||
        e.name === "build" ||
        e.name === "coverage" ||
        e.name === ".next" ||
        e.name === "out" ||
        e.name === "cjs" ||
        e.name === "esm" ||
        e.name === "umd"
      ) {
        continue;
      }
      await collectJsFiles(full, maxFiles, maxDepth, curDepth + 1, acc);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      // skip obvious minified/bundle files
      if (
        e.name.endsWith(".min.js") ||
        e.name.includes("bundle") ||
        e.name.includes("webpack")
      ) {
        continue;
      }
      acc.push(full);
    }
  }

  return acc;
}

async function checkMaintainerDormancy(packageName, monthsThreshold = 12) {
  const url = `https://registry.npmjs.org/${packageName}`;
  let data;

  try {
    const res = await axios.get(url);
    data = res.data;
  } catch (e) {
    return {
      package: packageName,
      error: e.message,
      hasTimeMetadata: false,
      dormant: null,
      diffMonths: null,
    };
  }

  const times = data.time || {};
  const latestVersion = data["dist-tags"]?.latest;
  const modified =
    times.modified || (latestVersion ? times[latestVersion] : null);

  if (!modified) {
    return {
      package: packageName,
      hasTimeMetadata: false,
      dormant: null,
      diffMonths: null,
    };
  }

  const lastPublish = new Date(modified);
  const now = new Date();

  const diffMonths =
    (now.getFullYear() - lastPublish.getFullYear()) * 12 +
    (now.getMonth() - lastPublish.getMonth());

  return {
    package: packageName,
    lastPublish,
    diffMonths,
    dormant: diffMonths >= monthsThreshold,
    hasTimeMetadata: true,
  };
}

app.get("/scan/obfuscation", async (req, res) => {
  try {
    const targetDir = req.query.dir
      ? path.resolve(req.query.dir)
      : path.join(__dirname, "package");
    let pkgJsonPath = path.join(targetDir, "package.json");
    if (!fsSync.existsSync(pkgJsonPath)) {
      const alt = path.join(targetDir, "package", "package.json");
      if (fsSync.existsSync(alt)) pkgJsonPath = alt;
      else
        return res
          .status(400)
          .json({ error: "package.json not found", dir: targetDir });
    }
    const realRoot = path.dirname(pkgJsonPath);
    const jsFiles = await collectJsFiles(realRoot);
    const results = [];
    for (const file of jsFiles) {
      try {
        const code = await fs.readFile(file, "utf8");
        results.push({
          file: path.relative(realRoot, file),
          obfuscated: isObfuscated(code),
        });
      } catch (e) {
        results.push({ file: path.relative(realRoot, file), error: e.message });
      }
    }
    const payload = { dir: realRoot, fileCount: jsFiles.length, results };
    await saveScanResult("obfuscationScan", payload);
    res.json(payload);
  } catch (err) {
    console.error("Error during obfuscation scan:", err.message);
    res
      .status(500)
      .json({ error: "Obfuscation scan failed", details: err.message });
  }
});

app.get("/scan/dns", async (req, res) => {
  try {
    const networkInterface = "en0";

    const { stdout } = await execAsync(
      `tshark -i ${networkInterface} -a duration:10 -Y "dns" -T fields -e dns.qry.name`
    );

    let domains = stdout
      .split("\n")
      .map((d) => d.trim())
      .filter((d) => d);

    domains = Array.from(new Set(domains));

    if (domains.length === 0) {
      return res.json({ message: "No DNS queries captured", domains: [] });
    }

    const maxQueries = 5;
    const selectedDomains = domains.slice(0, maxQueries);

    const queryVirusTotal = async (domain) => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 1000));

        const response = await axios.get(
          `https://www.virustotal.com/api/v3/domains/${domain}`,
          {
            headers: { "x-apikey": VIRUSTOTAL_API_KEY },
          }
        );

        return { domain, reputation: response.data };
      } catch (error) {
        console.error(
          `Error querying VirusTotal for ${domain}:`,
          error.message
        );
        return { domain, error: error.message };
      }
    };

    const results = await Promise.allSettled(
      selectedDomains.map(queryVirusTotal)
    );

    const finalResults = results.map((result) =>
      result.status === "fulfilled"
        ? result.value
        : {
            domain: result.reason?.domain || "unknown",
            error: result.reason?.message || "Unknown error",
          }
    );

    const dnsData = { domains: finalResults };

    await saveScanResult("dnsScan", dnsData);

    res.json(dnsData);
  } catch (err) {
    console.error("Error during DNS logging scan:", err);
    res.status(500).json({
      error: "DNS logging scan failed",
      details: err.message,
    });
  }
});

app.get("/scan/maintainer", async (req, res) => {
  const pkg = req.query.package;

  if (!pkg) {
    return res.status(400).json({
      error:
        "Missing 'package' query parameter. Example: /scan/maintainer?package=lodash",
    });
  }

  try {
    const result = await checkMaintainerDormancy(pkg);

    await saveScanResult("maintainerDormancy", result);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      error: "Maintainer dormancy scan failed",
      details: err.message,
    });
  }
});

app.listen(PORT, () => {
  console.log(
    `Security scanning service started. Access it at http://localhost:${PORT}`
  );
});
