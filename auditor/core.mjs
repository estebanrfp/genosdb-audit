import { createHash } from "node:crypto"
import { readFile, realpath, stat } from "node:fs/promises"
import path from "node:path"

const SHA256 = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{2,79}$/
const RUN_ID = /^[a-z0-9][a-z0-9-]{7,79}$/

export const CAPABILITIES = Object.freeze([
  "signed-operations",
  "roles",
  "acl",
  "encrypted-records",
  "replay",
  "reordering",
  "partitions",
  "restart",
  "multi-peer",
  "persistence",
  "origin-isolation",
  "resource-bounds",
  "governance",
  "transport-direct",
  "transport-delta",
  "transport-compressed-delta",
  "transport-full-state"
])

const CAPABILITY_SET = new Set(CAPABILITIES)
const EVIDENCE_TYPES = new Set([
  "snapshot",
  "packet",
  "transport-receipt",
  "browser-trace",
  "console",
  "network",
  "screenshot",
  "log",
  "state-diff"
])
const VERDICTS = new Set(["pass", "fail", "inconclusive"])

export const TEST_FAMILIES = Object.freeze([
  {
    id: "ZT-AUTH-001",
    title: "Unsigned operations are rejected",
    layer: "engine",
    oracle: "rejection",
    requires: ["signed-operations"],
    rationale: "A remote peer cannot create, update, link or remove state without a valid signer."
  },
  {
    id: "ZT-SIG-001",
    title: "Signed fields are bound to the signature",
    layer: "engine",
    oracle: "rejection",
    requires: ["signed-operations"],
    rationale: "Mutating content, id, identity, address, timestamp or signature after signing is rejected."
  },
  {
    id: "ZT-ROLE-001",
    title: "Role restrictions survive direct packet injection",
    layer: "engine",
    oracle: "rejection",
    requires: ["roles"],
    rationale: "Bypassing application helpers cannot bypass the receiver role gate."
  },
  {
    id: "ZT-ROLE-002",
    title: "Role self-escalation and stale promotion replay are rejected",
    layer: "engine",
    oracle: "rejection",
    requires: ["roles", "replay"],
    rationale: "A peer cannot grant itself authority or restore authority that was removed."
  },
  {
    id: "ZT-ACL-001",
    title: "Node ACL decisions are enforced by the honest receiver",
    layer: "engine",
    oracle: "rejection",
    requires: ["acl"],
    rationale: "No grant, read-only and revoked collaborators cannot mutate protected state."
  },
  {
    id: "ZT-ACL-002",
    title: "Non-owners cannot rewrite node policy",
    layer: "engine",
    oracle: "rejection",
    requires: ["acl"],
    rationale: "Owner, collaborators and cryptographic key envelopes remain owner-controlled."
  },
  {
    id: "ZT-SYNC-001",
    title: "Security decisions are invariant across synchronization envelopes",
    layer: "protocol",
    oracle: "convergence",
    requiresAny: [
      "transport-direct",
      "transport-delta",
      "transport-compressed-delta",
      "transport-full-state"
    ],
    variantCapabilities: {
      "transport-direct": "direct",
      "transport-delta": "delta",
      "transport-compressed-delta": "compressed-delta",
      "transport-full-state": "full-state"
    },
    rationale: "Every enabled transport path has a positive control and the same authorization boundary."
  },
  {
    id: "ZT-REPLAY-001",
    title: "Revoked authority is not restored by replay",
    layer: "protocol",
    oracle: "rejection",
    requires: ["replay"],
    rationale: "Old grants, promotions and signed writes cannot defeat newer authoritative state."
  },
  {
    id: "ZT-ORDER-001",
    title: "Duplicate and reordered delivery preserves invariants",
    layer: "protocol",
    oracle: "rejection",
    requires: ["reordering"],
    rationale: "Network scheduling cannot convert a denied sequence into an accepted one."
  },
  {
    id: "ZT-PART-001",
    title: "A stale peer cannot regain authority after a partition",
    layer: "protocol",
    oracle: "rejection",
    requires: ["partitions", "multi-peer"],
    rationale: "Revocation remains effective when an offline peer rejoins with stale signed state."
  },
  {
    id: "ZT-FRESH-001",
    title: "Fresh peer catch-up preserves provenance and policy",
    layer: "protocol",
    oracle: "convergence",
    requires: ["multi-peer", "restart"],
    rationale: "A new receiver reconstructs only valid state and reaches the authorized result."
  },
  {
    id: "ZT-ENC-001",
    title: "Encrypted access is prospectively revoked",
    layer: "engine",
    oracle: "confidentiality",
    requires: ["encrypted-records"],
    rationale: "A stale reader cannot decrypt a post-rotation version or restore an old key envelope."
  },
  {
    id: "ZT-GOV-001",
    title: "Governance metadata cannot manufacture authority",
    layer: "engine",
    oracle: "rejection",
    requires: ["governance"],
    rationale: "Priority, role claims and hostile clocks do not override the authority model."
  },
  {
    id: "ZT-ISO-001",
    title: "Peer identities and storage remain origin-isolated",
    layer: "harness",
    oracle: "isolation",
    requires: ["origin-isolation"],
    rationale: "Test peers do not accidentally share OPFS, storage, sessions or signing identity."
  },
  {
    id: "ZT-PERSIST-001",
    title: "Restart does not resurrect rejected or revoked state",
    layer: "engine",
    oracle: "rejection",
    requires: ["persistence", "restart"],
    rationale: "Durable storage and startup replay apply the same validation as live synchronization."
  },
  {
    id: "ZT-RESOURCE-001",
    title: "Malformed peer input is bounded without receiver loss",
    layer: "protocol",
    oracle: "boundedness",
    requires: ["resource-bounds"],
    rationale: "A bounded malformed corpus is rejected while a valid witness and the receiver remain responsive."
  }
])

export class AuditInputError extends Error {
  constructor(message, issues = []) {
    super(message)
    this.name = "AuditInputError"
    this.issues = issues
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]))
  }
  return value
}

export function stableJson(value) {
  return JSON.stringify(canonical(value))
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === "string" ? value : stableJson(value))
  return createHash("sha256").update(bytes).digest("hex")
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
}

function isContained(root, candidate) {
  const relative = path.relative(root, candidate)
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
}

function loopbackHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "")
  if (host === "localhost" || host === "::1") return true
  const match = host.match(/^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  return Boolean(match && match.slice(1).every((part) => Number(part) <= 255))
}

function parseScopedUrl(raw, protocols, label, issues) {
  let url
  try {
    url = new URL(raw)
  } catch {
    issues.push(`${label}: invalid URL`)
    return null
  }
  if (!protocols.includes(url.protocol)) issues.push(`${label}: protocol not allowed (${url.protocol})`)
  if (!loopbackHost(url.hostname)) issues.push(`${label}: only loopback is allowed; received ${url.hostname}`)
  if (url.username || url.password) issues.push(`${label}: URL credentials are not allowed`)
  return url
}

function validateManifestShape(manifest) {
  const issues = []
  if (!isRecord(manifest)) return ["The manifest must be a JSON object"]
  if (manifest.schemaVersion !== 1) issues.push("schemaVersion must be 1")
  if (typeof manifest.id !== "string" || !ID.test(manifest.id)) issues.push("id must be a stable lowercase identifier")
  if (typeof manifest.name !== "string" || manifest.name.trim().length < 3) issues.push("name is required")

  const auth = manifest.authorization
  if (!isRecord(auth)) issues.push("authorization is required")
  else {
    if (auth.mode !== "loopback-only") issues.push("authorization.mode must be loopback-only in this version")
    if (auth.readOnlyTarget !== true) issues.push("authorization.readOnlyTarget must be true")
    if (typeof auth.owner !== "string" || auth.owner.trim().length < 3) issues.push("authorization.owner is required")
    if (typeof auth.purpose !== "string" || auth.purpose.trim().length < 12) issues.push("authorization.purpose must describe the authorized test")
    if (typeof auth.targetRoot !== "string" || !auth.targetRoot.trim()) issues.push("authorization.targetRoot is required")
    if (typeof auth.harnessRoot !== "string" || !auth.harnessRoot.trim()) issues.push("authorization.harnessRoot is required")
    if (auth.expiresAt !== undefined && !Number.isFinite(Date.parse(auth.expiresAt))) issues.push("authorization.expiresAt is not a valid date")
  }

  const runtime = manifest.runtime
  if (!isRecord(runtime)) issues.push("runtime is required")
  else {
    if (typeof runtime.entryUrl !== "string") issues.push("runtime.entryUrl is required")
    if (!Array.isArray(runtime.allowedOrigins) || !runtime.allowedOrigins.length) issues.push("runtime.allowedOrigins must contain at least one origin")
    if (!Array.isArray(runtime.relayUrls)) issues.push("runtime.relayUrls must be an array")
  }

  const genosdb = manifest.genosdb
  if (!isRecord(genosdb)) issues.push("genosdb is required: this auditor only supports GenosDB")
  else {
    if (typeof genosdb.version !== "string" || !genosdb.version.trim()) issues.push("genosdb.version is required")
    if (genosdb.receiverModel !== "honest") issues.push("genosdb.receiverModel must be honest")
    if (genosdb.attackerModel !== "self-key-and-arbitrary-packets") {
      issues.push("genosdb.attackerModel must be self-key-and-arbitrary-packets")
    }
  }

  const adapter = manifest.adapter
  if (!isRecord(adapter) || typeof adapter.module !== "string" || !adapter.module.trim()) issues.push("adapter.module is required")
  if (!Array.isArray(manifest.capabilities) || !manifest.capabilities.length) issues.push("capabilities must contain at least one capability")
  else {
    const seen = new Set()
    for (const capability of manifest.capabilities) {
      if (!CAPABILITY_SET.has(capability)) issues.push(`unknown capability: ${capability}`)
      if (seen.has(capability)) issues.push(`duplicate capability: ${capability}`)
      seen.add(capability)
    }
  }
  if (!Array.isArray(manifest.artifacts) || !manifest.artifacts.length) issues.push("artifacts must pin at least one artifact")
  else {
    const names = new Set()
    for (const artifact of manifest.artifacts) {
      if (!isRecord(artifact) || typeof artifact.name !== "string" || typeof artifact.path !== "string") {
        issues.push("each artifact requires name and path")
        continue
      }
      if (!ID.test(artifact.name)) issues.push(`invalid artifact.name: ${artifact.name}`)
      if (names.has(artifact.name)) issues.push(`duplicate artifact: ${artifact.name}`)
      names.add(artifact.name)
    }
  }
  const minObservationMs = manifest.execution?.minObservationMs
  if (!Number.isInteger(minObservationMs) || minObservationMs < 250 || minObservationMs > 120_000) {
    issues.push("execution.minObservationMs must be an integer between 250 and 120000")
  }
  return issues
}

async function containedRealPath(root, input, label, kind = "file") {
  const candidate = await realpath(path.resolve(root, input))
  if (!isContained(root, candidate)) throw new AuditInputError(`${label} escapes the authorized root`, [candidate])
  const info = await stat(candidate)
  if (kind === "file" && !info.isFile()) throw new AuditInputError(`${label} is not a regular file`, [candidate])
  if (kind === "directory" && !info.isDirectory()) throw new AuditInputError(`${label} is not a directory`, [candidate])
  return candidate
}

export async function loadTarget(inputPath) {
  const requested = path.resolve(inputPath)
  let manifestPath
  let manifest
  try {
    manifestPath = await realpath(requested)
    manifest = JSON.parse(await readFile(manifestPath, "utf8"))
  } catch (error) {
    throw new AuditInputError(`Could not load the manifest: ${error.message}`)
  }

  const issues = validateManifestShape(manifest)
  if (issues.length) throw new AuditInputError("Invalid manifest", issues)
  if (manifest.authorization.expiresAt && Date.parse(manifest.authorization.expiresAt) <= Date.now()) {
    throw new AuditInputError("Target authorization has expired", [manifest.authorization.expiresAt])
  }

  const manifestDir = path.dirname(manifestPath)
  const targetRoot = await realpath(path.resolve(manifestDir, manifest.authorization.targetRoot))
  const harnessRoot = await realpath(path.resolve(manifestDir, manifest.authorization.harnessRoot))
  for (const [label, root] of [["targetRoot", targetRoot], ["harnessRoot", harnessRoot]]) {
    if ((await stat(root)).isDirectory() !== true) throw new AuditInputError(`${label} is not a directory`)
    if (root === path.parse(root).root) throw new AuditInputError(`${label} cannot be the filesystem root`)
  }

  const urlIssues = []
  const entry = parseScopedUrl(manifest.runtime.entryUrl, ["http:", "https:"], "runtime.entryUrl", urlIssues)
  const origins = []
  for (const [index, raw] of manifest.runtime.allowedOrigins.entries()) {
    const value = parseScopedUrl(raw, ["http:", "https:"], `runtime.allowedOrigins[${index}]`, urlIssues)
    if (value) origins.push(value.origin)
  }
  const relays = []
  for (const [index, raw] of manifest.runtime.relayUrls.entries()) {
    const value = parseScopedUrl(raw, ["ws:", "wss:"], `runtime.relayUrls[${index}]`, urlIssues)
    if (value) relays.push(value.href)
  }
  if (entry && !origins.includes(entry.origin)) urlIssues.push("runtime.allowedOrigins must include the entryUrl origin")
  if (new Set(origins).size !== origins.length) urlIssues.push("runtime.allowedOrigins contains duplicates")
  if (urlIssues.length) throw new AuditInputError("Invalid network scope", urlIssues)

  const adapterPath = await containedRealPath(harnessRoot, path.resolve(manifestDir, manifest.adapter.module), "adapter.module")
  const artifacts = []
  for (const artifact of manifest.artifacts) {
    const artifactPath = await containedRealPath(targetRoot, path.resolve(targetRoot, artifact.path), `artifact ${artifact.name}`)
    const bytes = await readFile(artifactPath)
    artifacts.push({ name: artifact.name, path: artifactPath, relativePath: path.relative(targetRoot, artifactPath), sha256: sha256(bytes) })
  }

  const normalized = {
    schemaVersion: 1,
    id: manifest.id,
    name: manifest.name,
    authorization: {
      mode: manifest.authorization.mode,
      owner: manifest.authorization.owner,
      purpose: manifest.authorization.purpose,
      expiresAt: manifest.authorization.expiresAt ?? null,
      readOnlyTarget: true
    },
    runtime: {
      entryUrl: entry.href,
      allowedOrigins: [...new Set(origins)].sort(),
      relayUrls: [...new Set(relays)].sort()
    },
    genosdb: canonical(manifest.genosdb),
    capabilities: [...manifest.capabilities].sort(),
    execution: { minObservationMs: manifest.execution.minObservationMs },
    artifacts: artifacts.map(({ name, relativePath, sha256: digest }) => ({ name, path: relativePath, sha256: digest })).sort((a, b) => a.name.localeCompare(b.name)),
    adapter: { id: manifest.adapter.id ?? path.basename(adapterPath), sha256: sha256(await readFile(adapterPath)) }
  }
  const targetFingerprint = sha256(normalized)
  const target = { manifestPath, targetRoot, harnessRoot, adapterPath, artifacts, normalized, targetFingerprint }
  return { ...target, plan: buildPlan(target) }
}

export function buildPlan(target) {
  const capabilities = new Set(target.normalized.capabilities)
  const selected = []
  const skipped = []
  for (const family of TEST_FAMILIES) {
    const missing = (family.requires ?? []).filter((item) => !capabilities.has(item))
    const hasAny = !family.requiresAny || family.requiresAny.some((item) => capabilities.has(item))
    if (missing.length || !hasAny) {
      skipped.push({
        id: family.id,
        title: family.title,
        missing: missing.length ? missing : family.requiresAny,
        reason: missing.length ? "missing-required-capabilities" : "missing-any-transport"
      })
      continue
    }
    const variants = family.variantCapabilities
      ? Object.entries(family.variantCapabilities).filter(([capability]) => capabilities.has(capability)).map(([, variant]) => variant)
      : []
    selected.push({
      id: family.id,
      title: family.title,
      layer: family.layer,
      oracle: family.oracle,
      rationale: family.rationale,
      variants
    })
  }
  const body = {
    schemaVersion: 1,
    targetId: target.normalized.id,
    targetFingerprint: target.targetFingerprint,
    selected,
    skipped
  }
  return { ...body, planFingerprint: sha256(body) }
}

function validEvidence(item, prefix, issues) {
  if (!isRecord(item)) {
    issues.push(`${prefix}: invalid evidence`)
    return
  }
  if (typeof item.id !== "string" || !ID.test(item.id)) issues.push(`${prefix}: invalid evidence.id`)
  if (!EVIDENCE_TYPES.has(item.type)) issues.push(`${prefix}: invalid evidence.type`)
  if (!SHA256.test(item.sha256 ?? "")) issues.push(`${prefix}: invalid evidence.sha256`)
  if (!Number.isFinite(Date.parse(item.createdAt))) issues.push(`${prefix}: invalid evidence.createdAt`)
}

function validatePassOracle(caseResult, family, minObservationMs, prefix, issues) {
  const oracle = caseResult.oracle
  if (!isRecord(oracle)) {
    issues.push(`${prefix}: oracle is missing`)
    return
  }
  if (oracle.kind !== family.oracle) issues.push(`${prefix}: oracle.kind must be ${family.oracle}`)
  if (oracle.assertionMet !== true) issues.push(`${prefix}: PASS requires oracle.assertionMet=true`)

  if (family.oracle === "rejection") {
    if (oracle.deliveryWitness !== true) issues.push(`${prefix}: rejection without a delivery witness`)
    if (!SHA256.test(oracle.beforeHash ?? "") || !SHA256.test(oracle.afterHash ?? "")) issues.push(`${prefix}: valid state hashes are missing`)
    else if (oracle.beforeHash !== oracle.afterHash) issues.push(`${prefix}: state changed in a rejection case`)
    if (!Number.isInteger(oracle.observationMs) || oracle.observationMs < minObservationMs) issues.push(`${prefix}: insufficient observation window`)
  } else if (family.oracle === "convergence") {
    if (oracle.deliveryWitness !== true) issues.push(`${prefix}: convergence without a delivery witness`)
    if (!SHA256.test(oracle.expectedHash ?? "") || !SHA256.test(oracle.actualHash ?? "")) issues.push(`${prefix}: valid convergence hashes are missing`)
    else if (oracle.expectedHash !== oracle.actualHash) issues.push(`${prefix}: state does not converge to the expected result`)
  } else if (family.oracle === "confidentiality") {
    if (oracle.authorizedControl !== true) issues.push(`${prefix}: authorized read positive control is missing`)
    if (oracle.unauthorizedPlaintextObserved !== false) issues.push(`${prefix}: absence of unauthorized plaintext was not demonstrated`)
    if (oracle.ownerRetainsAccess !== true) issues.push(`${prefix}: owner access control is missing`)
  } else if (family.oracle === "isolation") {
    if (oracle.controlObserved !== true || oracle.crossBoundaryLeakObserved !== false) issues.push(`${prefix}: incomplete isolation evidence`)
  } else if (family.oracle === "boundedness") {
    if (oracle.limitEnforced !== true || oracle.receiverResponsive !== true || oracle.validWitnessObserved !== true) {
      issues.push(`${prefix}: incomplete bounds or continuity evidence`)
    }
  }
}

export function verifyReceipt(target, receipt) {
  const issues = []
  const counts = { pass: 0, fail: 0, inconclusive: 0 }
  if (!isRecord(receipt)) return { valid: false, issues: ["The receipt must be a JSON object"], counts, coverage: {} }
  if (receipt.schemaVersion !== 1) issues.push("schemaVersion must be 1")
  if (typeof receipt.runId !== "string" || !RUN_ID.test(receipt.runId)) issues.push("invalid runId")
  if (receipt.targetFingerprint !== target.targetFingerprint) issues.push("targetFingerprint does not match the loaded target")
  if (receipt.planFingerprint !== target.plan.planFingerprint) issues.push("planFingerprint does not match the current plan")
  if (receipt.complete !== true) issues.push("the receipt is not marked complete")
  const started = Date.parse(receipt.startedAt)
  const finished = Date.parse(receipt.finishedAt)
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started) issues.push("invalid receipt time window")
  if (typeof receipt.seed !== "string" || receipt.seed.length < 8) issues.push("seed must identify the run")

  const families = new Map(target.plan.selected.map((family) => [family.id, family]))
  const coverage = Object.fromEntries(target.plan.selected.map((family) => [family.id, new Set()]))
  const caseIds = new Set()
  if (!Array.isArray(receipt.cases) || !receipt.cases.length) issues.push("cases must contain results")
  else for (const [index, caseResult] of receipt.cases.entries()) {
    const prefix = `cases[${index}]`
    if (!isRecord(caseResult)) {
      issues.push(`${prefix}: invalid case`)
      continue
    }
    if (typeof caseResult.id !== "string" || !ID.test(caseResult.id)) issues.push(`${prefix}: invalid id`)
    else if (caseIds.has(caseResult.id)) issues.push(`${prefix}: duplicate id ${caseResult.id}`)
    else caseIds.add(caseResult.id)
    const family = families.get(caseResult.familyId)
    if (!family) {
      issues.push(`${prefix}: familyId does not belong to the plan (${caseResult.familyId})`)
      continue
    }
    coverage[family.id].add(caseResult.variant ?? "default")
    if (!VERDICTS.has(caseResult.verdict)) {
      issues.push(`${prefix}: invalid verdict`)
      continue
    }
    counts[caseResult.verdict]++
    if (typeof caseResult.expected !== "string" || !caseResult.expected.trim()) issues.push(`${prefix}: expected is required`)
    if (typeof caseResult.actual !== "string" || !caseResult.actual.trim()) issues.push(`${prefix}: actual is required`)

    if (caseResult.verdict === "inconclusive") {
      if (typeof caseResult.reason !== "string" || caseResult.reason.trim().length < 5) issues.push(`${prefix}: INCONCLUSIVE requires a reason`)
      continue
    }

    if (!Array.isArray(caseResult.preconditions) || !caseResult.preconditions.length) issues.push(`${prefix}: verifiable preconditions are missing`)
    else for (const [preIndex, precondition] of caseResult.preconditions.entries()) {
      if (!isRecord(precondition) || typeof precondition.id !== "string" || precondition.passed !== true) {
        issues.push(`${prefix}.preconditions[${preIndex}]: an unmet precondition must produce INCONCLUSIVE`)
      }
    }
    if (!Array.isArray(caseResult.evidence) || !caseResult.evidence.length) issues.push(`${prefix}: PASS/FAIL requires machine evidence`)
    else caseResult.evidence.forEach((item, evidenceIndex) => validEvidence(item, `${prefix}.evidence[${evidenceIndex}]`, issues))

    if (caseResult.verdict === "pass") validatePassOracle(caseResult, family, target.normalized.execution.minObservationMs, prefix, issues)
    if (caseResult.verdict === "fail" && caseResult.oracle?.assertionMet !== false) issues.push(`${prefix}: FAIL requires oracle.assertionMet=false`)
  }

  for (const family of target.plan.selected) {
    const observed = coverage[family.id]
    if (!observed.size) issues.push(`no executed coverage for ${family.id}`)
    for (const variant of family.variants) if (!observed.has(variant)) issues.push(`missing variant ${family.id}/${variant}`)
  }
  if (isRecord(receipt.counts)) {
    for (const key of Object.keys(counts)) if (receipt.counts[key] !== counts[key]) issues.push(`inconsistent count: ${key}`)
  } else issues.push("counts is required")

  return {
    valid: issues.length === 0,
    issues,
    counts,
    coverage: Object.fromEntries(Object.entries(coverage).map(([id, variants]) => [id, [...variants].sort()]))
  }
}
