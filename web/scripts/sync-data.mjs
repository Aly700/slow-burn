import { readFile, writeFile, readdir, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { convertScores } from "./csv.mjs";
import { normalizeRecording } from "./live-recordings.mjs";

const web = fileURLToPath(new URL("../", import.meta.url));
const source = path.resolve(web, "../artifacts");
const dest = path.join(web, "public/data");
await mkdir(dest, { recursive: true });
const warnings = [];
async function files(dir) {
  try {
    return await readdir(dir);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}
async function json(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    warnings.push(`${path.basename(file)}: ${error.code ?? "invalid JSON"}`);
    return null;
  }
}
async function write(name, value) {
  await writeFile(path.join(dest, name), JSON.stringify(value, null, 2) + "\n");
}
// Includes replay_2025.json and future additive contract artifacts.
const artifacts = {};
for (const name of await files(source)) {
  if (!name.endsWith(".json")) continue;
  artifacts[name.slice(0, -5)] = await json(path.join(source, name));
  await write(name, artifacts[name.slice(0, -5)]);
}
let scores = [];
try {
  scores = convertScores(
    await readFile(path.join(source, "scores_2026_top5000.csv"), "utf8"),
  );
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  warnings.push("Scores are not available yet");
}
await write("scores_2026_top5000.json", scores);
const runDir = path.join(source, "agent_runs");
const recorded = (await files(runDir)).filter((name) =>
  /^CVE-[\d-]+\.json$/.test(name),
);
const useFixtures = recorded.length === 0;
const selectedDir = useFixtures ? path.join(web, "fixtures") : runDir;
const runs = [];
await rm(path.join(dest, "agent_runs"), { recursive: true, force: true });
await mkdir(path.join(dest, "agent_runs"), { recursive: true });
for (const name of (await files(selectedDir))
  .filter((name) => /^CVE-[\d-]+\.json$/.test(name))
  .sort()) {
  const run = await json(path.join(selectedDir, name));
  if (!run?.cve_id || !run?.run_id) continue;
  runs.push(run);
  await write(`agent_runs/${name}`, run);
}
async function findVerifierExample(directory) {
  for (const name of (await files(directory)).sort()) {
    const file = path.join(directory, name);
    if (name.endsWith(".json")) {
      const run = await json(file);
      if (
        run?.run_id &&
        Array.isArray(run.verifier?.dropped) &&
        run.verifier.dropped.length
      )
        return run;
    } else {
      try {
        const found = await findVerifierExample(file);
        if (found) return found;
      } catch (error) {
        if (error.code !== "ENOTDIR") throw error;
      }
    }
  }
  return null;
}
const verifierExample = useFixtures ? null : await findVerifierExample(runDir);
const liveExamples = [];
const liveDir = path.join(runDir, "live-examples");
for (const name of (await files(liveDir)).filter(name => /\.jsonl?$/.test(name)).sort()) {
  try {
    const raw = await readFile(path.join(liveDir, name), "utf8");
    const source = name.endsWith(".jsonl") ? raw.trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) : JSON.parse(raw);
    const recording = normalizeRecording(source);
    if (!recording) { warnings.push(`${name}: incomplete live recording; using trace fallback`); continue; }
    liveExamples.push(recording);
    await mkdir(path.join(dest, "agent_runs/live-examples"), { recursive: true });
    await write(`agent_runs/live-examples/${name.replace(/\.jsonl$/, ".json")}`, recording);
  } catch { warnings.push(`${name}: unreadable live recording; using trace fallback`); }
}
const bundle = {
  ...artifacts,
  scores,
  runs,
  verifier_example: verifierExample,
  live_examples: liveExamples,
  meta: {
    synced_at: new Date().toISOString(),
    runs_source: useFixtures ? "fixtures" : "recorded",
    score_mode:
      scores.some(
        (row) => row.score != null && (row.score > 1 || row.score < 0),
      ) || /baseline/i.test(artifacts.model_card?.model ?? "")
        ? "ranking"
        : "probability",
    warnings,
  },
};
await write("bundle.json", bundle);
console.log(
  `Synced ${Object.keys(artifacts).length} artifacts, ${scores.length} scores, ${runs.length} ${useFixtures ? "fixture" : "recorded"} briefings.`,
);
for (const warning of warnings) console.warn(warning);
