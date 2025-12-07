// Randomly sample N packages with a fixed seed.
const fs = require("fs");

// simple seed-based RNG
function makeRng(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 0xffffffff;
  };
}

const inputFile = process.argv[2];
const sampleSize = parseInt(process.argv[3] || "1000", 10);
const outputFile = process.argv[4] || "packages.txt";

if (!inputFile) {
  console.error("Usage: node sample_packages.js <input_file> [n] [output]");
  process.exit(1);
}

const rng = makeRng(20250801);

const lines = fs
  .readFileSync(inputFile, "utf8")
  .split("\n")
  .map((x) => x.trim())
  .filter(Boolean);

console.log("Total packages:", lines.length);

for (let i = lines.length - 1; i > 0; i--) {
  const j = Math.floor(rng() * (i + 1));
  [lines[i], lines[j]] = [lines[j], lines[i]];
}

const out = lines.slice(0, sampleSize);
fs.writeFileSync(outputFile, out.join("\n"));

console.log(`Wrote ${out.length} packages -> ${outputFile}`);
console.log("Seed used:", 20250801);
