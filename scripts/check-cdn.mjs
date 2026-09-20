import { mkdir, writeFile } from "node:fs/promises"
import { ENTRY_URL, verifyCdnLatest } from "./cdn.mjs"

const directory = new URL("../.runtime/", import.meta.url)
const statusPath = new URL("cdn.json", directory)
const save = (status) => writeFile(statusPath, JSON.stringify(status, null, 2) + "\n")

await mkdir(directory, { recursive: true })
const pending = {
  schemaVersion: 1,
  kind: "genosdb-cdn-provenance",
  scope: "cdn-version-and-byte-consistency-only",
  securityAudit: false,
  verified: false,
  entryUrl: ENTRY_URL,
  checkedAt: new Date().toISOString()
}
// Invalidate a previous successful result before starting a new network check.
await save(pending)
try {
  const result = await verifyCdnLatest()
  await save(result)
  console.log(JSON.stringify(result, null, 2))
} catch (error) {
  const result = { ...pending, checkedAt: new Date().toISOString(), error: error.message }
  await save(result)
  console.error(JSON.stringify(result, null, 2))
  process.exitCode = 1
}
