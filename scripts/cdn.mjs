import { createHash } from "node:crypto"

export const BASE = "https://cdn.jsdelivr.net/npm/genosdb@latest/"
export const ENTRY_URL = `${BASE}dist/index.min.js`
export const MAX_BYTES = 8_000_000
const FILES = ["index.min.js", "index.js", "sm.min.js", "sm-acls.min.js", "sm-gov.min.js", "genosrtc.min.js", "genossrv.min.js"]
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex")

async function retrieve(url, fetcher) {
  const response = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(20_000) })
  if (!response.ok) throw new Error(`CDN returned HTTP ${response.status}: ${url}`)
  if (Number(response.headers.get("content-length")) > MAX_BYTES) {
    await response.body?.cancel()
    throw new Error("CDN artifact exceeds the size limit")
  }
  if (!response.body) throw new Error("CDN returned an empty body")
  const reader = response.body.getReader()
  const chunks = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_BYTES) {
        await reader.cancel()
        throw new Error("CDN artifact exceeds the size limit")
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  if (!size) throw new Error("CDN returned an empty artifact")
  const bytes = Buffer.concat(chunks)
  return { bytes, url, size, version: response.headers.get("x-jsd-version"), sha256: hash(bytes) }
}

export async function verifyCdnLatest(fetcher = fetch) {
  const manifest = await retrieve(`${BASE}package.json`, fetcher)
  const metadata = JSON.parse(manifest.bytes.toString("utf8"))
  if (metadata.name !== "genosdb" || typeof metadata.version !== "string" ||
      !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(metadata.version)) {
    throw new Error("Invalid GenosDB CDN metadata")
  }
  const version = metadata.version
  if (manifest.version !== version) throw new Error("Package version header is inconsistent")
  const latest = await retrieve(ENTRY_URL, fetcher)
  if (latest.version !== version) throw new Error("The latest entry version is inconsistent; retry")
  const pinnedBase = `https://cdn.jsdelivr.net/npm/genosdb@${version}/dist/`
  const artifacts = []
  for (const name of FILES) {
    const result = await retrieve(`${pinnedBase}${name}`, fetcher)
    if (result.version !== version) throw new Error(`Unexpected version header for ${name}`)
    artifacts.push({ name, url: result.url, size: result.size, sha256: result.sha256 })
  }
  if (artifacts[0].sha256 !== latest.sha256) throw new Error("Latest entry bytes differ from the pinned version")
  return {
    schemaVersion: 1,
    kind: "genosdb-cdn-provenance",
    scope: "cdn-version-and-byte-consistency-only",
    securityAudit: false,
    verified: true,
    checkedAt: new Date().toISOString(),
    version,
    resolution: "latest-once-then-pinned-version",
    packageUrl: manifest.url,
    packageSha256: manifest.sha256,
    entryUrl: ENTRY_URL,
    entrySha256: latest.sha256,
    artifacts
  }
}
