import assert from "node:assert/strict"
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { AuditInputError, loadTarget, sha256, verifyReceipt } from "./core.mjs"

const root = await mkdtemp(path.join(os.tmpdir(), "genosdb-auditor-"))
const targetRoot = path.join(root, "target")
const harnessRoot = path.join(root, "harness")
const manifests = path.join(root, "manifests")

function evidence(id) {
  return { id, type: "snapshot", sha256: sha256(id), createdAt: "2026-09-20T00:00:01.000Z" }
}

function rejection(id, familyId) {
  const stateHash = sha256(`${id}-state`)
  return {
    id,
    familyId,
    verdict: "pass",
    expected: "The honest receiver rejects the hostile operation.",
    actual: "The valid witness arrived and protected state remained unchanged.",
    preconditions: [{ id: "transport-witness", passed: true }],
    evidence: [evidence(`${id}-snapshot`)],
    oracle: {
      kind: "rejection",
      assertionMet: true,
      deliveryWitness: true,
      beforeHash: stateHash,
      afterHash: stateHash,
      observationMs: 500
    }
  }
}

try {
  await mkdir(targetRoot)
  await mkdir(harnessRoot)
  await mkdir(manifests)
  await writeFile(path.join(targetRoot, "bundle.js"), "export const version = 'fixture'\n")
  await writeFile(path.join(harnessRoot, "adapter.mjs"), "export default { protocolVersion: 1 }\n")

  const manifest = {
    schemaVersion: 1,
    id: "fixture-target",
    name: "Fixture target",
    authorization: {
      mode: "loopback-only",
      owner: "self-test",
      purpose: "Exercise fail-closed auditor validation",
      targetRoot: "../target",
      harnessRoot: "../harness",
      readOnlyTarget: true
    },
    runtime: {
      entryUrl: "http://127.0.0.1:4173/",
      allowedOrigins: ["http://127.0.0.1:4173"],
      relayUrls: ["ws://127.0.0.1:8765"]
    },
    genosdb: {
      version: "fixture",
      receiverModel: "honest",
      attackerModel: "self-key-and-arbitrary-packets"
    },
    adapter: { module: "../harness/adapter.mjs" },
    capabilities: ["signed-operations", "transport-direct"],
    artifacts: [{ name: "fixture-bundle", path: "bundle.js" }],
    execution: { minObservationMs: 500 }
  }
  const manifestPath = path.join(manifests, "target.json")
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  const target = await loadTarget(manifestPath)
  assert.equal(target.plan.selected.length, 3)
  assert.deepEqual(target.plan.selected.map((item) => item.id), ["ZT-AUTH-001", "ZT-SIG-001", "ZT-SYNC-001"])

  const expectedHash = sha256("converged")
  const receipt = {
    schemaVersion: 1,
    runId: "fixture-run-0001",
    targetFingerprint: target.targetFingerprint,
    planFingerprint: target.plan.planFingerprint,
    seed: "fixture-seed-0001",
    startedAt: "2026-09-20T00:00:00.000Z",
    finishedAt: "2026-09-20T00:00:02.000Z",
    complete: true,
    counts: { pass: 3, fail: 0, inconclusive: 0 },
    cases: [
      rejection("unsigned-put", "ZT-AUTH-001"),
      rejection("tampered-content", "ZT-SIG-001"),
      {
        id: "positive-direct",
        familyId: "ZT-SYNC-001",
        variant: "direct",
        verdict: "pass",
        expected: "The authorized operation converges.",
        actual: "The receiver contains the signed value.",
        preconditions: [{ id: "peers-ready", passed: true }],
        evidence: [evidence("positive-direct-snapshot")],
        oracle: {
          kind: "convergence",
          assertionMet: true,
          deliveryWitness: true,
          expectedHash,
          actualHash: expectedHash
        }
      }
    ]
  }
  assert.deepEqual(verifyReceipt(target, receipt).issues, [])

  const falsePass = structuredClone(receipt)
  falsePass.cases[0].evidence = []
  assert.equal(verifyReceipt(target, falsePass).valid, false)

  const outOfScope = structuredClone(manifest)
  outOfScope.runtime.entryUrl = "https://example.com/"
  outOfScope.runtime.allowedOrigins = ["https://example.com"]
  const outOfScopePath = path.join(manifests, "out-of-scope.json")
  await writeFile(outOfScopePath, `${JSON.stringify(outOfScope, null, 2)}\n`)
  await assert.rejects(() => loadTarget(outOfScopePath), AuditInputError)

  const wrongEngine = structuredClone(manifest)
  delete wrongEngine.genosdb
  const wrongEnginePath = path.join(manifests, "wrong-engine.json")
  await writeFile(wrongEnginePath, `${JSON.stringify(wrongEngine, null, 2)}\n`)
  await assert.rejects(() => loadTarget(wrongEnginePath), AuditInputError)

  await symlink(path.join(harnessRoot, "adapter.mjs"), path.join(targetRoot, "escaped.js"))
  const escaped = structuredClone(manifest)
  escaped.artifacts = [{ name: "escaped-artifact", path: "escaped.js" }]
  const escapedPath = path.join(manifests, "escaped.json")
  await writeFile(escapedPath, `${JSON.stringify(escaped, null, 2)}\n`)
  await assert.rejects(() => loadTarget(escapedPath), AuditInputError)

  console.log("Auditor self-test: 7 PASS, 0 FAIL")
} finally {
  await rm(root, { recursive: true, force: true })
}
