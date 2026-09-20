# Security

## Reporting

Report suspected security problems privately to the maintainer at **estebanrfp@gmail.com**. Avoid public issues containing credentials, sensitive records, or operational reproduction payloads. Include the affected repository version, expected behavior, observed behavior and non-sensitive provenance information.

For suspected GenosDB engine issues, identify the exact GenosDB version separately from the version of this reviewer. A FAIL receipt needs causal review; it is not sufficient attribution by itself.

## Data Handling

The reviewer processes local files. It does not upload receipts or evidence. `cdn:verify` contacts only the official jsDelivr GenosDB paths and does not send local audit data. Its generated provenance file is ignored by Git.

Treat all received manifests and receipts as untrusted input. Review file paths before loading them. No untrusted adapter or downloaded JavaScript is executed by this release. Report validation checks consistency, not the truth of the producer's observations.
