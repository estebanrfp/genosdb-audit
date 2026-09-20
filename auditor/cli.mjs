#!/usr/bin/env node

import { readFile } from "node:fs/promises"
import { AuditInputError, loadTarget, verifyReceipt } from "./core.mjs"

function usage() {
  console.error("Usage: node auditor/cli.mjs <validate|plan|verify> <target.json> [receipt.json] [--json]")
  process.exitCode = 2
}

function printTarget(target) {
  console.log(`Target: ${target.normalized.name} (${target.normalized.id})`)
  console.log(`Scope: ${target.normalized.authorization.mode}`)
  console.log(`Target root: ${target.targetRoot}`)
  console.log(`Harness root: ${target.harnessRoot}`)
  console.log(`Fingerprint: ${target.targetFingerprint}`)
  console.log(`Pinned artifacts: ${target.artifacts.length}`)
  console.log(`Applicable families: ${target.plan.selected.length}/${target.plan.selected.length + target.plan.skipped.length}`)
}

async function main() {
  const [command, manifestPath, receiptPath] = process.argv.slice(2).filter((arg) => arg !== "--json")
  const json = process.argv.includes("--json")
  if (!command || !manifestPath || !["validate", "plan", "verify"].includes(command)) return usage()

  const target = await loadTarget(manifestPath)
  if (command === "validate") {
    if (json) console.log(JSON.stringify({ valid: true, ...target.normalized, targetFingerprint: target.targetFingerprint }, null, 2))
    else {
      printTarget(target)
      console.log("Result: valid loopback-only manifest")
    }
    return
  }

  if (command === "plan") {
    if (json) console.log(JSON.stringify(target.plan, null, 2))
    else {
      printTarget(target)
      console.log(`Plan: ${target.plan.planFingerprint}`)
      console.log("\nApplicable:")
      for (const family of target.plan.selected) {
        const variants = family.variants.length ? ` [${family.variants.join(", ")}]` : ""
        console.log(`  ${family.id} ${family.layer}/${family.oracle}${variants} - ${family.title}`)
      }
      console.log("\nDeclared exclusions:")
      for (const family of target.plan.skipped) console.log(`  ${family.id} - missing ${family.missing.join(", ")}`)
    }
    return
  }

  if (!receiptPath) return usage()
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"))
  const result = verifyReceipt(target, receipt)
  if (json) console.log(JSON.stringify(result, null, 2))
  else {
    printTarget(target)
    console.log(`Receipt: ${receipt.runId ?? "(no id)"}`)
    console.log(`Counts: ${result.counts.pass} PASS, ${result.counts.fail} FAIL, ${result.counts.inconclusive} INCONCLUSIVE`)
    if (result.issues.length) {
      console.log("Receipt checks: INVALID")
      for (const issue of result.issues) console.log(`  - ${issue}`)
    } else console.log("Receipt checks: VALID (observations are not independently verified)")
  }
  if (!result.valid) process.exitCode = 2
  else if (result.counts.fail || result.counts.inconclusive) process.exitCode = 1
}

main().catch((error) => {
  if (error instanceof AuditInputError) {
    console.error(error.message)
    for (const issue of error.issues) console.error(`  - ${issue}`)
  } else console.error(error.stack || error.message || String(error))
  process.exitCode = 2
})
