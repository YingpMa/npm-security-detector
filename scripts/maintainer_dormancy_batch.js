// Checks npm packages for publish inactivity.
// A package is marked dormant if it has not been published for 12 months or more.
const fs = require("fs").promises;
const path = require("path");
const axios = require("axios");

async function checkDormancy(packageName, monthsThreshold = 12) {
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

async function main() {
  const dataDir = path.join(__dirname, "..", "dataset");
  const listPath = path.join(dataDir, "packages.txt");

  const resultsDir = path.join(__dirname, "..", "maintainer");
  await fs.mkdir(resultsDir, { recursive: true });

  const outPath = path.join(resultsDir, "maintainer_dormancy.json");

  const raw = await fs.readFile(listPath, "utf8");
  const packages = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  console.log(`Total packages loaded: ${packages.length}`);

  const results = [];

  for (const pkg of packages) {
    console.log("Checking:", pkg);
    try {
      const info = await checkDormancy(pkg);
      results.push(info);
    } catch (err) {
      results.push({ package: pkg, error: err.message });
    }
  }

  await fs.writeFile(outPath, JSON.stringify(results, null, 2), "utf8");
  console.log(`\nSaved dormancy results to ${outPath}`);
}

main().catch((e) => {
  console.error("Batch failed", e);
  process.exit(1);
});
