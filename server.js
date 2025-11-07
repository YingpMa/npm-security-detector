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

async function checkGitHubSecurityAdvisory(packageName, version) {
  const query = `
    query {
      securityVulnerabilities(
        first: 10,
        ecosystem: NPM,
        package: "${packageName}"
      ) {
        nodes {
          advisory {
            summary
            severity
          }
          vulnerableVersionRange
        }
      }
    }
  `;
  try {
    const response = await axios.post(
      "https://api.github.com/graphql",
      { query },
      { headers: { Authorization: `Bearer ${GITHUB_TOKEN}` } }
    );
    return response.data;
  } catch (error) {
    console.error(
      `Error querying GitHub Advisory for ${packageName}:`,
      error.message
    );
    return null;
  }
}

// ---------------- 1. npm 漏洞扫描（不动你现有的） ----------------
app.get("/scan/npm", async (req, res) => {
  try {
    const { stdout } = await execAsync("npm audit --json");
    let auditResults = JSON.parse(stdout);

    if (auditResults.advisories) {
      let enriched = [];
      for (let id in auditResults.advisories) {
        let adv = auditResults.advisories[id];
        let version =
          adv.findings && adv.findings[0] && adv.findings[0].version;
        let ghData = await checkGitHubSecurityAdvisory(
          adv.module_name,
          version
        );
        enriched.push({ npmAdvisory: adv, githubAdvisory: ghData });
      }
      auditResults.enriched = enriched;
    }
    await saveScanResult("npmScan", auditResults);
    res.json({ auditResults });
  } catch (err) {
    console.error("Error during npm scan:", err);
    res.status(500).json({ error: "npm scan failed", details: err.message });
  }
});

// ---------------- 2. C2 检测（不动） ----------------
app.get("/scan/c2", async (req, res) => {
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

    const c2Data = { domains: finalResults };
    await saveScanResult("c2Scan", c2Data);
    res.json(c2Data);
  } catch (err) {
    console.error("Error during C2 scan:", err);
    res.status(500).json({ error: "C2 scan failed", details: err.message });
  }
});

// ---------------- 3. 风险分数（不动） ----------------
app.get("/scan/score", async (req, res) => {
  try {
    let vulnerabilityCount = 0;
    let c2Count = 0;
    let githubHighRiskCount = 0;

    let { stdout: npmStdout } = await execAsync("npm audit --json");
    let auditResults = JSON.parse(npmStdout);
    if (auditResults.metadata && auditResults.metadata.vulnerabilities) {
      vulnerabilityCount = Object.values(
        auditResults.metadata.vulnerabilities
      ).reduce((sum, count) => sum + count, 0);
    }
    if (auditResults.advisories) {
      for (let id in auditResults.advisories) {
        let adv = auditResults.advisories[id];
        if (adv.severity === "high" || adv.severity === "critical") {
          githubHighRiskCount++;
        }
      }
    }

    let { stdout: tsharkStdout } = await execAsync(
      'tshark -a duration:10 -Y "dns" -T fields -e dns.qry.name'
    );
    let domains = tsharkStdout.split("\n").filter((line) => line.trim() !== "");
    domains = Array.from(new Set(domains));
    c2Count = domains.length;

    const riskScore =
      vulnerabilityCount + c2Count * 2 + githubHighRiskCount * 3;
    const scoreResult = {
      vulnerabilityCount,
      c2Count,
      githubHighRiskCount,
      riskScore,
    };
    await saveScanResult("riskScore", scoreResult);
    res.json(scoreResult);
  } catch (err) {
    console.error("Error calculating risk score:", err);
    res
      .status(500)
      .json({ error: "Risk score calculation failed", details: err.message });
  }
});

// ---------------- 4. 报表（不动） ----------------
app.get("/report", async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ error: "MongoDB not connected" });
    }
    const collection = db.collection("scanResults");
    const results = await collection.find({}).sort({ timestamp: -1 }).toArray();
    res.json(results);
  } catch (err) {
    console.error("Error retrieving report:", err);
    res
      .status(500)
      .json({ error: "Report retrieval failed", details: err.message });
  }
});

// --------- replace existing /scan/obfuscation with this ---------
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
      if (e.name === "node_modules") continue;
      await collectJsFiles(full, maxFiles, maxDepth, curDepth + 1, acc);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      acc.push(full);
    }
  }
  return acc;
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

app.listen(PORT, () => {
  console.log(
    `Security scanning service started. Access it at http://localhost:${PORT}`
  );
});
