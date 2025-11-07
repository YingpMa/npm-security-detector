const fs = require("fs");

function makeRNG(seed) {
  let s = seed >>> 0;
  return function () {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0xffffffff;
  };
}

const inputFile = process.argv[2]; //  filtered_packages.txt
const sampleSize = parseInt(process.argv[3] || "1000", 10);
const outputFile = process.argv[4] || "packages.txt";
// seed
const rng = makeRNG(20250801);

if (!inputFile) {
  console.error(
    "Usage: node sample_packages.js <input_file> [sample_size] [output_file]"
  );
  process.exit(1);
}

const all = fs
  .readFileSync(inputFile, "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter(Boolean);

console.log(`Total packages available: ${all.length}`);

for (let i = all.length - 1; i > 0; i--) {
  const j = Math.floor(rng() * (i + 1));
  [all[i], all[j]] = [all[j], all[i]];
}

const sample = all.slice(0, sampleSize);

fs.writeFileSync(outputFile, sample.join("\n"), "utf8");
console.log(`✅ Saved ${sample.length} packages to ${outputFile}`);
console.log(`Seed: 20250801`);
