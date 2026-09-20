import assert from "node:assert/strict"
import test from "node:test"
import { fileURLToPath } from "node:url"
import { execFileSync, spawnSync } from "node:child_process"
import { mkdtemp, writeFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { loadTarget, sha256, verifyReceipt } from "../auditor/core.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))
const manifestPath = fileURLToPath(new URL("../examples/target.json", import.meta.url))
const target = await loadTarget(manifestPath)
const digest = sha256("inert synthetic state")
function receipt() {
  return {
    schemaVersion: 1,
    runId: "synthetic-review-0001",
    targetFingerprint: target.targetFingerprint,
    planFingerprint: target.plan.planFingerprint,
    seed: "synthetic-review-seed",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:03.000Z",
    complete: true,
    counts: { pass: 2, fail: 0, inconclusive: 0 },
    cases: target.plan.selected.map((family, index) => ({
      id: `synthetic-case-${index}`,
      familyId: family.id,
      verdict: "pass",
      expected: "Synthetic consistency check only",
      actual: "Synthetic assertion; no GenosDB instance was run",
      preconditions: [{ id: "synthetic-precondition", passed: true }],
      evidence: [{ id: `synthetic-evidence-${index}`, type: "snapshot", sha256: digest, createdAt: "2026-01-01T00:00:01.000Z" }],
      oracle: { kind: "rejection", assertionMet: true, deliveryWitness: true, beforeHash: digest, afterHash: digest, observationMs: 500 }
    }))
  }
}

test("synthetic consistent receipt passes review without establishing observed truth", () => {
  assert.equal(verifyReceipt(target, receipt()).valid, true)
})

const invalidCases = [
  ["missing delivery witness", (r) => { r.cases[0].oracle.deliveryWitness = false }],
  ["changed receiver hash", (r) => { r.cases[0].oracle.afterHash = sha256("different fixture") }],
  ["insufficient observation", (r) => { r.cases[0].oracle.observationMs = 10 }],
  ["missing evidence reference", (r) => { r.cases[0].evidence = [] }],
  ["incomplete receipt", (r) => { r.complete = false }],
  ["wrong target fingerprint", (r) => { r.targetFingerprint = digest }],
  ["wrong counts", (r) => { r.counts.pass = 99 }],
  ["duplicate case id", (r) => { r.cases[1].id = r.cases[0].id }],
  ["missing family coverage", (r) => { r.cases.pop(); r.counts.pass = 1 }],
  ["unmet precondition", (r) => { r.cases[0].preconditions[0].passed = false }]
]
for (const [name, change] of invalidCases) {
  test(`rejects ${name}`, () => {
    const data = receipt()
    change(data)
    assert.equal(verifyReceipt(target, data).valid, false)
  })
}

test("FAIL and INCONCLUSIVE remain distinct from PASS", () => {
  for (const verdict of ["fail", "inconclusive"]) {
    const data = receipt()
    data.cases[0].verdict = verdict
    data.cases[0].oracle.assertionMet = false
    data.cases[0].reason = "Synthetic unavailable observation"
    data.counts = { pass: 1, fail: 0, inconclusive: 0, [verdict]: 1 }
    const result = verifyReceipt(target, data)
    assert.equal(result.valid, true)
    assert.equal(result.counts[verdict], 1)
  }
})

test("CLI plans offline and rejects an unknown command", () => {
  const plan = JSON.parse(execFileSync(process.execPath, ["auditor/cli.mjs", "plan", manifestPath, "--json"], { cwd: root, encoding: "utf8" }))
  assert.equal(plan.selected.length, 2)
  assert.equal(plan.skipped.length, 14)
  assert.equal(spawnSync(process.execPath, ["auditor/cli.mjs", "execute", manifestPath], { cwd: root }).status, 2)
})

test("CLI exit codes distinguish passing, failed and invalid receipts", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "genosdb-reviewer-"))
  try {
    const file = path.join(directory, "synthetic.json")
    const data = receipt()
    for (const [mode, expected] of [["pass", 0], ["fail", 1], ["invalid", 2]]) {
      if (mode === "fail") {
        data.cases[0].verdict = "fail"
        data.cases[0].oracle.assertionMet = false
        data.counts = { pass: 1, fail: 1, inconclusive: 0 }
      }
      if (mode === "invalid") data.complete = false
      await writeFile(file, JSON.stringify(data))
      const result = spawnSync(process.execPath, ["auditor/cli.mjs", "verify", manifestPath, file, "--json"], { cwd: root })
      assert.equal(result.status, expected)
      assert.equal(JSON.parse(result.stdout).valid, mode !== "invalid")
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
