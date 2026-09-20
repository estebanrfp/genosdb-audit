# GenosDB Zero Trust Verification Model

The security subject is an honest GenosDB receiver enforcing documented authentication and authorization. Peers are not trusted merely because they can communicate. Owner key theft is outside this model; copied credentials do not test the receiver's enforcement boundary.

| Family | Obligation |
| --- | --- |
| ZT-AUTH-001 | Require authentic operations |
| ZT-SIG-001 | Bind signed fields to signatures |
| ZT-ROLE-001 | Enforce receiver-side roles |
| ZT-ROLE-002 | Preserve role authority |
| ZT-ACL-001 | Enforce per-node access decisions |
| ZT-ACL-002 | Keep policy changes owner-controlled |
| ZT-SYNC-001 | Apply consistent validation across synchronization paths |
| ZT-REPLAY-001 | Preserve revocation against historical state |
| ZT-ORDER-001 | Preserve invariants across delivery ordering |
| ZT-PART-001 | Preserve authority after peer rejoin |
| ZT-FRESH-001 | Preserve provenance during catch-up |
| ZT-ENC-001 | Enforce prospective cryptographic revocation |
| ZT-GOV-001 | Prevent metadata from manufacturing authority |
| ZT-ISO-001 | Isolate test identities and storage |
| ZT-PERSIST-001 | Preserve validation across restart |
| ZT-RESOURCE-001 | Preserve receiver continuity within declared bounds |

## Results

- PASS: the declared assertion and required controls are recorded as satisfied.
- FAIL: recorded evidence contradicts the declared assertion; attribution remains separate.
- INCONCLUSIVE: setup, delivery, observation or another precondition is insufficient.

For rejection, the record must include a delivery witness, unchanged state hashes and a sufficient observation interval. Authorized positive controls must establish that a receiver is functioning. A timeout alone is not evidence of rejection.

Pin artifact hashes, policy assumptions, version, scope, topology and observation time when making claims. One passing representative does not exhaust a family. A finite campaign cannot establish rejection of every possible input or schedule.

The CLI checks the structure and consistency of these claims; it does not run the campaign or independently verify observations. See the README's trust boundary before interpreting a valid receipt.
