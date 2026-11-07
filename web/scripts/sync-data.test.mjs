import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  cp,
  writeFile,
  readFile,
  rm,
  readdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

test("sync handles absent inputs, then replaces fixtures with recorded runs without changing source", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "btb-sync-"));
  const web = path.join(root, "web");
  try {
    await mkdir(path.join(web, "scripts"), { recursive: true });
    await mkdir(path.join(web, "fixtures"));
    for (const name of ["sync-data.mjs", "csv.mjs"])
      await cp(new URL(name, import.meta.url), path.join(web, "scripts", name));
    await writeFile(
      path.join(web, "fixtures", "CVE-2026-1.json"),
      JSON.stringify({ run_id: "fixture", cve_id: "CVE-2026-1" }),
    );
    const sync = () => {
      const result = spawnSync(
        process.execPath,
        [path.join(web, "scripts/sync-data.mjs")],
        { cwd: tmpdir(), encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
    };
    const bundle = async () =>
      JSON.parse(
        await readFile(path.join(web, "public/data/bundle.json"), "utf8"),
      );
    sync();
    assert.equal((await bundle()).meta.runs_source, "fixtures");
    assert.deepEqual((await bundle()).scores, []);
    await mkdir(path.join(root, "artifacts/agent_runs"), { recursive: true });
    const record = JSON.stringify({
      run_id: "recorded",
      cve_id: "CVE-2026-2",
      state: "WAITING_APPROVAL",
    });
    await writeFile(
      path.join(root, "artifacts/agent_runs/CVE-2026-2.json"),
      record,
    );
    await writeFile(
      path.join(root, "artifacts/model_card.json"),
      JSON.stringify({ model: "final" }),
    );
    await writeFile(
      path.join(root, "artifacts/findings.json"),
      JSON.stringify({ headline: { ours_hits_top500_2025_backtest: null } }),
    );
    await writeFile(
      path.join(root, "artifacts/scores_2026_top5000.csv"),
      "rank,cve_id,score,epss,reasons\n1,CVE-2026-2,0.2,,[]\n",
    );
    await mkdir(path.join(root, "artifacts/agent_runs/eval"));
    await writeFile(path.join(root, "artifacts/agent_runs/eval/review.json"), JSON.stringify({
      run_id: "verifier-example", cve_id: "CVE-2025-3",
      verifier: { dropped: [{ id: "unsupported", text: "Unsupported example", why: "No evidence" }] },
    }));
    sync();
    const result = await bundle();
    assert.equal(result.verifier_example.run_id, "verifier-example");
    assert.equal(result.meta.runs_source, "recorded");
    assert.equal(result.meta.score_mode, "probability");
    assert.equal(result.scores[0].epss, null);
    assert.equal(result.runs.length, 1);
    assert.equal(result.runs[0].run_id, "recorded");
    assert.deepEqual(await readdir(path.join(web, "public/data/agent_runs")), [
      "CVE-2026-2.json",
    ]);
    assert.equal(
      await readFile(
        path.join(root, "artifacts/agent_runs/CVE-2026-2.json"),
        "utf8",
      ),
      record,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
