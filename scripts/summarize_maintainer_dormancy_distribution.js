// scripts/summarize_maintainer_dormancy_distribution.js

const fs = require("fs");
const path = require("path");

function main() {
  const ROOT = path.resolve(__dirname, "..");

  // input file
  const input = path.join(ROOT, "maintainer", "maintainer_dormancy.json");

  // FIX — add missing line
  const summaryDir = path.join(ROOT, "maintainer", "summary");

  const outPath = path.join(
    summaryDir,
    "maintainer_dormancy_distribution.json"
  );

  if (!fs.existsSync(input)) {
    console.error("ERROR: maintainer_dormancy.json not found");
    process.exit(1);
  }

  fs.mkdirSync(summaryDir, { recursive: true });

  const entries = JSON.parse(fs.readFileSync(input, "utf8"));
  const total = entries.length;

  const bins = {
    "0-3": 0,
    "3-6": 0,
    "6-12": 0,
    ">12": 0,
    missing: 0,
  };

  const dormantList = [];
  let withMetadata = 0;

  for (const e of entries) {
    if (!e.hasTimeMetadata || e.diffMonths === null) {
      bins.missing++;
      continue;
    }

    withMetadata++;

    const m = e.diffMonths;

    if (m <= 3) bins["0-3"]++;
    else if (m <= 6) bins["3-6"]++;
    else if (m <= 12) bins["6-12"]++;
    else {
      bins[">12"]++;
      dormantList.push(e);
    }
  }

  function pct(x, base) {
    return base ? x / base : 0;
  }

  const output = {
    totalPackages: total,
    withMetadata,
    missingMetadata: bins.missing,
    bins,
    share: {
      "0-3": pct(bins["0-3"], total),
      "3-6": pct(bins["3-6"], total),
      "6-12": pct(bins["6-12"], total),
      ">12": pct(bins[">12"], total),
      missing: pct(bins.missing, total),
    },
    dormantPackages: dormantList.length,
    dormantShareOfAll: pct(dormantList.length, total),
    dormantShareOfWithMetadata: pct(dormantList.length, withMetadata),
    topDormant: dormantList
      .sort((a, b) => b.diffMonths - a.diffMonths)
      .slice(0, 20)
      .map((x) => ({
        package: x.package,
        diffMonths: x.diffMonths,
        lastPublish: x.lastPublish,
      })),
  };

  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log("Saved:", outPath);
  console.log(output);
}

main();
