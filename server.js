/**
 * Extended npm Supply Chain Security Scanning Tool
 *
 * Features:
 * 1. /scan/npm    - Runs "npm audit" to check for vulnerabilities in project dependencies,
 *                   and enriches the results by querying the GitHub Security Advisory API for high-risk packages.
 * 2. /scan/c2     - Uses tshark to capture DNS queries for 10 seconds and queries the VirusTotal API for domain reputation (C2 detection).
 * 3. /scan/score  - Computes a comprehensive risk score based on vulnerabilities, C2 connections, and high-risk dependencies.
 * 4. /report      - Retrieves historical scan reports from MongoDB.
 * 5. /scan/obfuscation - Performs dependency obfuscation detection by scanning package files.
 *
 * Requirements:
 * - Install Wireshark/tshark (e.g., on Ubuntu: sudo apt install tshark, on macOS: brew install wireshark)
 * - Install Node.js.
 * - Run a MongoDB service (default connection: mongodb://localhost:27017)
 * - Install the necessary npm packages:
 *       npm install express axios mongodb dotenv
 * - Configure your VirusTotal API Key and GitHub Token by setting them in a .env file.
 */

require("dotenv").config();

const fs = require("fs").promises; // Promise-based fs API
const fsSync = require("fs"); // Synchronous fs API (for existsSync)
const path = require("path");
const express = require("express");
const axios = require("axios");
const { exec } = require("child_process");
const util = require("util");
const { MongoClient } = require("mongodb");

// Promisify exec for async/await usage
const execAsync = util.promisify(exec);

const app = express();
const PORT = 3050;

// Get API keys from environment variables
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

// MongoDB configuration
const mongoUrl = "mongodb://localhost:27017";
const dbName = "supplyChainSecurity";
let db;

// Connect to MongoDB
MongoClient.connect(mongoUrl, { useUnifiedTopology: true })
  .then((client) => {
    db = client.db(dbName);
    console.log("Connected to MongoDB successfully");
  })
  .catch((err) => console.error("MongoDB connection error:", err));

/**
 * Save scan results to MongoDB.
 * @param {string} type - Scan type (e.g., 'npmScan', 'c2Scan', 'riskScore', 'obfuscationScan')
 * @param {Object} data - Scan result data
 */
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

/**
 * Check GitHub Security Advisory for a given npm package.
 * @param {string} packageName - Name of the npm package
 * @param {string} version - Current version of the package
 * @returns {Object|null} - Data returned from GitHub or null on error
 */
async function checkGitHubSecurityAdvisory(packageName, version) {
  // Construct GraphQL query (customize as needed)
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

// -----------------------------------------------------------------------------
// 1. npm Dependency Vulnerability Scan (with GitHub Advisory check)
//    Runs "npm audit --json", parses the vulnerability report, and for each advisory,
//    queries the GitHub Security Advisory API.
app.get("/scan/npm", async (req, res) => {
  try {
    // Run npm audit to get the vulnerability report in JSON format
    let { stdout } = await execAsync("npm audit --json");
    let auditResults = JSON.parse(stdout);

    // If advisories exist, enrich each advisory with GitHub data
    if (auditResults.advisories) {
      let enriched = [];
      for (let id in auditResults.advisories) {
        let adv = auditResults.advisories[id];
        // Use the first finding's version as an example
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
    // Save npm scan result to MongoDB
    await saveScanResult("npmScan", auditResults);
    res.json({ auditResults });
  } catch (err) {
    console.error("Error during npm scan:", err);
    res.status(500).json({ error: "npm scan failed", details: err.message });
  }
});

// -----------------------------------------------------------------------------
// 2. C2 Connection Detection
//    Uses tshark to capture DNS queries for 10 seconds and queries the VirusTotal API
//    for each captured domain.

app.get("/scan/c2", async (req, res) => {
  try {
    // 🛠️ 自动检测默认 Wi-Fi 网卡
    const networkInterface = "en0"; // 默认值，如果需要自动检测，可用 `tshark -D` 手动查看
    console.log(`🌍 Using network interface: ${networkInterface}`);

    // 🕵️ 捕获 DNS 查询数据（10 秒）
    const { stdout } = await execAsync(
      `tshark -i ${networkInterface} -a duration:10 -Y "dns" -T fields -e dns.qry.name`
    );

    // 🛠️ 解析 DNS 结果
    let domains = stdout
      .split("\n")
      .map((d) => d.trim())
      .filter((d) => d);
    domains = Array.from(new Set(domains)); // 去重

    console.log("📡 Captured DNS queries:", domains);

    if (domains.length === 0) {
      console.log("⚠️ No DNS queries captured.");
      return res.json({ message: "No DNS queries captured", domains: [] });
    }

    // 🌍 限制最大查询数量（防止 VirusTotal API 封锁）
    const maxQueries = 5;
    const selectedDomains = domains.slice(0, maxQueries);
    console.log(`🔍 Querying VirusTotal for up to ${maxQueries} domains...`);

    // 🔗 批量查询 VirusTotal API（使用并发）
    const queryVirusTotal = async (domain) => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 1000)); // ⏳ 防止 API 速率限制
        const response = await axios.get(
          `https://www.virustotal.com/api/v3/domains/${domain}`,
          {
            headers: { "x-apikey": VIRUSTOTAL_API_KEY },
          }
        );
        return { domain, reputation: response.data };
      } catch (error) {
        console.error(
          `❌ Error querying VirusTotal for ${domain}:`,
          error.message
        );
        return { domain, error: error.message };
      }
    };

    // ⚡ 并发请求 VirusTotal API
    const results = await Promise.allSettled(
      selectedDomains.map(queryVirusTotal)
    );

    // 🗂️ 结构化响应数据
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

    // 📡 返回扫描结果
    res.json(c2Data);
  } catch (err) {
    console.error("🚨 Error during C2 scan:", err);
    res.status(500).json({ error: "C2 scan failed", details: err.message });
  }
});

// -----------------------------------------------------------------------------
// 3. Comprehensive Risk Score Calculation
//    Combines npm vulnerabilities, C2 connection count, and GitHub high-risk dependencies.
//    Risk Score = Vulnerability Count + (C2 Connection Count * 2) + (High-risk Dependency Count * 3)
app.get("/scan/score", async (req, res) => {
  try {
    let vulnerabilityCount = 0;
    let c2Count = 0;
    let githubHighRiskCount = 0;

    // ① Run npm audit to get vulnerability info
    let { stdout: npmStdout } = await execAsync("npm audit --json");
    let auditResults = JSON.parse(npmStdout);
    if (auditResults.metadata && auditResults.metadata.vulnerabilities) {
      vulnerabilityCount = Object.values(
        auditResults.metadata.vulnerabilities
      ).reduce((sum, count) => sum + count, 0);
    }
    // Count high-risk dependencies based on advisories (e.g., severity high or critical)
    if (auditResults.advisories) {
      for (let id in auditResults.advisories) {
        let adv = auditResults.advisories[id];
        if (adv.severity === "high" || adv.severity === "critical") {
          githubHighRiskCount++;
        }
      }
    }

    // ② Capture DNS queries using tshark as an indicator for C2 connections
    let { stdout: tsharkStdout } = await execAsync(
      'tshark -a duration:10 -Y "dns" -T fields -e dns.qry.name'
    );
    let domains = tsharkStdout.split("\n").filter((line) => line.trim() !== "");
    domains = Array.from(new Set(domains));
    c2Count = domains.length;

    // ③ Calculate the comprehensive risk score
    const riskScore =
      vulnerabilityCount + c2Count * 2 + githubHighRiskCount * 3;
    const scoreResult = {
      vulnerabilityCount,
      c2Count,
      githubHighRiskCount,
      riskScore,
    };
    // Save risk score result to MongoDB
    await saveScanResult("riskScore", scoreResult);
    res.json(scoreResult);
  } catch (err) {
    console.error("Error calculating risk score:", err);
    res
      .status(500)
      .json({ error: "Risk score calculation failed", details: err.message });
  }
});

// -----------------------------------------------------------------------------
// 4. Historical Scan Report
//    Retrieves all scan records from MongoDB, sorted by timestamp (newest first)
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

// -----------------------------------------------------------------------------
// 5. Dependency Obfuscation Detection
//    Scans each dependency's main file (or first JS file) to heuristically detect obfuscation.
function isObfuscated(code) {
  // Split code into lines
  const lines = code.split("\n");
  // If there is only one line and the length is very long, it might be obfuscated or minified
  if (lines.length === 1 && code.length > 1000) {
    return true;
  }
  // Calculate average line length
  const avgLineLength = code.length / lines.length;
  if (avgLineLength > 200) {
    return true;
  }
  return false;
}

app.get("/scan/obfuscation", async (req, res) => {
  try {
    // Read the project's package.json file
    const packageJsonPath = path.join(__dirname, "package.json");
    const packageJsonData = await fs.readFile(packageJsonPath, "utf8");
    const packageJson = JSON.parse(packageJsonData);
    const dependencies = packageJson.dependencies || {};

    let results = [];

    // Iterate over each dependency
    for (let dep in dependencies) {
      try {
        // Get dependency's package.json path
        const depPackageJsonPath = path.join(
          __dirname,
          "node_modules",
          dep,
          "package.json"
        );
        const depPackageJsonData = await fs.readFile(
          depPackageJsonPath,
          "utf8"
        );
        const depPackageJson = JSON.parse(depPackageJsonData);

        // Get main file; if not defined, default to "index.js"
        let mainFile = depPackageJson.main || "index.js";
        let mainFilePath = path.join(__dirname, "node_modules", dep, mainFile);

        // Check if main file exists using synchronous fs API
        if (!fsSync.existsSync(mainFilePath)) {
          const depDir = path.join(__dirname, "node_modules", dep);
          const files = await fs.readdir(depDir);
          const jsFiles = files.filter((file) => file.endsWith(".js"));
          if (jsFiles.length > 0) {
            mainFile = jsFiles[0]; // choose the first .js file
            // Reassign mainFilePath without redeclaring it
            mainFilePath = path.join(depDir, mainFile);
          }
        }

        // Read the main file code
        const code = await fs.readFile(mainFilePath, "utf8");
        // Use heuristic to detect obfuscation
        const obfuscated = isObfuscated(code);
        results.push({ dependency: dep, obfuscated });
      } catch (err) {
        console.error(`Error scanning dependency ${dep}:`, err.message);
        results.push({ dependency: dep, error: err.message });
      }
    }
    // Save obfuscation scan result to MongoDB
    await saveScanResult("obfuscationScan", results);
    res.json(results);
  } catch (err) {
    console.error("Error during obfuscation scan:", err.message);
    res
      .status(500)
      .json({ error: "Obfuscation scan failed", details: err.message });
  }
});

// -----------------------------------------------------------------------------
// Start the Express server
app.listen(PORT, () => {
  console.log(
    `Security scanning service started. Access it at http://localhost:${PORT}`
  );
});
