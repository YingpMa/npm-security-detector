const fs = require("fs");
const https = require("https");

const target = parseInt(process.argv[2] || "10000", 10);
const outFile = process.argv[3] || "all_top10000.txt";

// 多放点词，避免一两个词被限就啥也没有
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

// 每个关键词最多翻几页
const PAGES_PER_QUERY = 8;
// 降到 150，别一上来就是 250
const PAGE_SIZE = 150;
// 被限速后休息多久（毫秒）
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
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          // 这里先判断是不是被 Cloudflare 挡了
          if (data.includes("error code: 1015")) {
            return reject(new Error("RATE_LIMIT_1015"));
          }
          try {
            const json = JSON.parse(data);
            resolve(json);
          } catch (e) {
            reject(e);
          }
        });
      })
      .on("error", reject);
  });
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  for (const q of QUERY_LIST) {
    console.log(`🔍 query="${q}"`);
    for (let p = 0; p < PAGES_PER_QUERY; p++) {
      if (collected.size >= target) break;

      const from = p * PAGE_SIZE;
      console.log(`  page ${p} (from=${from})`);

      let ok = false;
      let tries = 0;
      while (!ok && tries < 3) {
        tries++;
        try {
          const data = await fetchSearch(q, from);
          const objs = data.objects || [];
          if (objs.length === 0) {
            console.log("  (no more results for this query)");
            ok = true;
            break;
          }
          for (const item of objs) {
            const name = item?.package?.name;
            if (name) collected.add(name);
          }
          console.log(`  collected so far: ${collected.size}`);
          ok = true;
          // 小停一下
          await sleep(300);
        } catch (e) {
          if (e.message === "RATE_LIMIT_1015") {
            console.warn("  ⚠️ rate limited, sleeping...");
            await sleep(RATE_LIMIT_SLEEP);
          } else {
            console.warn(`  ⚠️ failed: ${e.message}`);
            await sleep(800);
          }
        }
      }
    }
    if (collected.size >= target) break;
  }

  const finalList = Array.from(collected).slice(0, target);
  fs.writeFileSync(outFile, finalList.join("\n"), "utf8");
  console.log(`✅ saved ${finalList.length} packages to ${outFile}`);
})();
