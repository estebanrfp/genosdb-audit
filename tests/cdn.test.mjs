import assert from "node:assert/strict"
import test from "node:test"
import { BASE, ENTRY_URL, MAX_BYTES, verifyCdnLatest } from "../scripts/cdn.mjs"

const version = "1.2.3"
function fixture(override = () => undefined) {
  const requests = []
  const fetcher = async (url, options) => {
    requests.push(url)
    assert.equal(new URL(url).origin, "https://cdn.jsdelivr.net")
    assert.equal(options.redirect, "error")
    assert.ok(options.signal instanceof AbortSignal)
    const replacement = override(url)
    if (replacement) return replacement
    const body = url === `${BASE}package.json`
      ? JSON.stringify({ name: "genosdb", version })
      : "This is synthetic inert fixture data, not executable JavaScript."
    return new Response(body, { headers: { "x-jsd-version": version } })
  }
  return { requests, fetcher }
}

test("latest is resolved once and version-pinned files are fingerprinted", async () => {
  const { fetcher, requests } = fixture()
  const result = await verifyCdnLatest(fetcher)
  assert.equal(result.verified, true)
  assert.equal(result.securityAudit, false)
  assert.equal(result.version, version)
  assert.equal(result.artifacts.length, 7)
  assert.equal(requests.length, 9)
  assert.equal(requests.filter((url) => url.includes("@latest")).length, 2)
  assert.ok(result.artifacts.every((entry) => entry.url.includes("@1.2.3/") && /^[a-f0-9]{64}$/.test(entry.sha256)))
})

test("inconsistent latest version is rejected", async () => {
  const { fetcher } = fixture((url) => url === ENTRY_URL && new Response("fixture", { headers: { "x-jsd-version": "1.2.2" } }))
  await assert.rejects(verifyCdnLatest(fetcher), /latest entry version/)
})

test("inconsistent entry bytes are rejected", async () => {
  const { fetcher } = fixture((url) => url === ENTRY_URL && new Response("different fixture", { headers: { "x-jsd-version": version } }))
  await assert.rejects(verifyCdnLatest(fetcher), /entry bytes differ/)
})

test("HTTP failure is not a successful check", async () => {
  const { fetcher } = fixture(() => new Response("unavailable", { status: 503 }))
  await assert.rejects(verifyCdnLatest(fetcher), /HTTP 503/)
})

test("invalid package metadata is rejected", async () => {
  const { fetcher } = fixture(() => new Response(JSON.stringify({ name: "unrelated", version })))
  await assert.rejects(verifyCdnLatest(fetcher), /Invalid GenosDB/)
})

test("declared oversized response is rejected", async () => {
  const { fetcher } = fixture(() => new Response("fixture", { headers: { "content-length": String(MAX_BYTES + 1) } }))
  await assert.rejects(verifyCdnLatest(fetcher), /size limit/)
})

test("streamed oversized response is rejected without a length header", async () => {
  const { fetcher } = fixture(() => new Response(new Uint8Array(MAX_BYTES + 1)))
  await assert.rejects(verifyCdnLatest(fetcher), /size limit/)
})

test("empty body is rejected", async () => {
  const { fetcher } = fixture(() => new Response(""))
  await assert.rejects(verifyCdnLatest(fetcher), /empty artifact/)
})

test("inconsistent pinned module version is rejected", async () => {
  const { fetcher } = fixture((url) => url.endsWith("/sm.min.js") && new Response("fixture", { headers: { "x-jsd-version": "1.2.2" } }))
  await assert.rejects(verifyCdnLatest(fetcher), /Unexpected version header/)
})
