// Collects up to 10k npm package names by running multiple keyword searches against the npm registry.

const fs = require("fs");
const https = require("https");

const target = parseInt(process.argv[2] || "10000", 10);
const outFile = process.argv[3] || "all_top10000.txt";

// Keywords for broad coverage
const QUERY_LIST = [
  "react",
  "core",
  "lib",
  "util",
  "plugin",
  "a",
  "e",
  "i",
  "o",
  "u",
  "s",
  "t",
  "r",
  "n",
  "api",
  "node",
  "js",
  "1",
  "2",
  "3",
  "4",
  "5",
];

// Fetch depth and size
const PAGES_PER_QUERY = 8;
const PAGE_SIZE = 150;
const RATE_LIMIT_SLEEP = 4000;

const collected = new Set();

function fetchSearch(q, from = 0) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(
    q
  )}&size=${PAGE_SIZE}&from=${from}`;

  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (data.includes("error code: 1015"))
            return reject(new Error("RATE_LIMIT_1015"));
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(err);
          }
        });
      })
      .on("error", reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  for (const q of QUERY_LIST) {
    console.log(`query="${q}"`);

    for (let p = 0; p < PAGES_PER_QUERY; p++) {
      if (collected.size >= target) break;

      const from = p * PAGE_SIZE;
      console.log(`  page ${p} (from=${from})`);

      let tries = 0;
      let ok = false;

      while (!ok && tries < 3) {
        tries++;
        try {
          const data = await fetchSearch(q, from);
          const objs = data.objects || [];
          if (objs.length === 0) {
            console.log("  no more results");
            ok = true;
            break;
          }

          for (const item of objs) {
            const name = item?.package?.name;
            if (name) collected.add(name);
          }

          console.log(`  collected: ${collected.size}`);
          ok = true;
          await sleep(300);
        } catch (e) {
          if (e.message === "RATE_LIMIT_1015") {
            console.log("  rate limited, sleeping...");
            await sleep(RATE_LIMIT_SLEEP);
          } else {
            console.log(`  error: ${e.message}`);
            await sleep(800);
          }
        }
      }
    }

    if (collected.size >= target) break;
  }

  const finalList = Array.from(collected).slice(0, target);
  fs.writeFileSync(outFile, finalList.join("\n"), "utf8");
  console.log(`saved ${finalList.length} packages to ${outFile}`);
})();
