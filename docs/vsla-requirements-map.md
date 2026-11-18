# VSLA requirements → qudisclose

Where each normative requirement of [VSLA v1.0, revision 2](https://github.com/AAI-Society/vsla/blob/main/spec/v1.0/requirements.md)
lives in this codebase, and the test that pins it. "n/a" means the requirement is on a role qudisclose does not play
in that configuration; "not claimed" means the seam exists but the guarantee is not asserted. Byte-compatibility with the
reference verifier (`tools/vsla_verify.py` in the vsla repository) is pinned by `tests/test_vsla_interop.py`.

## Finder (qudisclose attesting its own cases)

| Id | Requirement (short) | Code | Test |
|---|---|---|---|
| VSLA-F-1 | signed in-toto/DSSE statement; RFC 8785 canonical bodies | `vsla/canonical.py`, `vsla/dsse.py`, `vsla/attest.py::Attestor._sign` | `test_vsla_interop.py::test_canonical_json_is_byte_identical_to_the_reference`, `test_vsla.py::test_pipeline_emits_finding_and_patch_statements_in_both_profiles` |
| VSLA-F-2 | subject = report digest + git commit; `reproduction.revision` equals it | `attest.py::report_digest`, `Attestor._common`; `orchestrator.run_case` captures `sandbox.revision()` before the test is added | pipeline test (`gitCommit == HEAD == reproduction.revision`); reference E3 in the interop test |
| VSLA-F-3 | MBOM: every model with family and serving mode; real weight digest or `unmeasured: true`, never a hash of the name | `orchestrator.py::Orchestrator._mbom`, `_entry`, `_weights`; `attest.py::MBOMEntry`, `model_family` | `test_mbom_weights_are_measured_or_unmeasured_never_the_model_name` |
| VSLA-F-4 | RFC 6962 root over every turn and tool call; leaf 0 is `measure`; a `verify` leaf agrees with `reproduction` | `vsla/transcript.py`, `vsla/merkle.py`; `run_case` measures before any turn | pipeline test; `test_inclusion_proof_lets_a_finder_reveal_one_leaf`; reference E5 |
| VSLA-F-5 | reproduction executed by code; `securityFailure` from the normative classifier | `security/sandbox.py::run_classified` (pytest junit: collected ≥ 1, assertion failure ≥ 1, errors = 0, no timeout), `Orchestrator._rerun` | `test_classifier_accepts_only_assertion_failures_in_collected_tests`; `test_hunter.py::test_hunter_rejects_broken_test_that_fails_for_wrong_reason` |
| VSLA-F-6 | patch: apply + reproduction + suite in a clean checkout; diff digest; files touched or digest; scope | `Orchestrator._verify_patch`, `Attestor.patch` | pipeline test (`pp["patch"]`) |
| VSLA-F-7 | untrusted input wrapping, injection flags in statement | `security/scanner.py`, `Attestor._common` (`injection`) | `test_security.py` |
| VSLA-F-8 | stable Ed25519 finder identity | `cli.py::_attest_key` (`keys/attestation.json`) | `test_cli_verify_attestation` |
| VSLA-F-9 | operator + harness digest in statement | `Attestor.__init__`, `attest.py::harness_digest` | E1/I1 checks |
| VSLA-F-10 | disclose through the declared channel, name it and the platform key | `Attestor.channel` (set from `public_url` + platform key) | `test_submitted_statement_is_reexecuted_at_revision_receipted_and_verified_l2` (I2) |
| VSLA-F-11 | ledger root + summary in statement; the entries handed over | `vsla/ledger.py::Ledger.summary`; the bundle's `ledger` list | same (claimed L2); `test_self_reported_history_fails_i4` |
| VSLA-F-12 | no non-authoritative release | publishing only through the publisher; outcome `non-authoritative-release` in `Ledger.OUTCOMES` | rubric zeroes it (reference tests) |
| VSLA-F-13 | serving mode declared | `_mbom` | E4/N1 |
| VSLA-F-14 | measured harness + sandbox as leaf 0 | `TranscriptRecorder.measure`, `attest.py::harness_digest`, `sandbox_digest` | N2 in the pipeline and interop tests (with the platform's own harness expectation) |
| VSLA-F-15..17 | attested environment, quote-bound enclave key, provider weight attestations | `vsla/environment.py` (reference `signed-quote` adapter; `quote_body` binds enclaveKey, harness, weights, sandbox), `dsse.py::make_weights_attestation` | `test_api_served_model_caps_environment_at_l2_and_attested_tee_reaches_l3`; **not claimed** for hardware TEEs |
| VSLA-F-18 | Patch L2 is `scope: source-only` | `attest.py::NON_SOURCE_PATTERNS`, `scope_of`, `diff_paths` | `test_submitted_patch_statement_is_reexecuted_reviewed_and_scoped` (mixed caps at L1) |
| VSLA-F-19 | authorization basis in every statement; recorded, not enforced | `VSLAConfig.authorization_basis/ref`, `Attestor.authorization`; `hunter.py::is_authorized` + `HunterConfig.authorized_targets` | pipeline test; `test_hunter.py::test_hunter_refuses_without_allowlist` |
| VSLA-F-20 | key rotation / revocation via validity windows | `vsla/keyring.py::Keyring` (`validFrom`, `revokedAt`; I1 checks the window at `finishedAt`) | reference `test_revoked_finder_key_fails_i1` (same code path in `verify.py`) |

Both profiles are produced for every statement (`vsla_<track>` embargoed, `vsla_<track>_published` plaintext); the MCP surface returns only the embargoed one until the case is public.

## Platform (qudisclose receiving statements)

| Id | Requirement (short) | Code | Test |
|---|---|---|---|
| VSLA-P-1 | verify every statement; record claimed, each check with its kind, verified, in the audit log | `Orchestrator._vsla_claimed`, `_vsla_receipt`, `vsla/verify.py` (`Check.kind`) | `..._receipted_and_verified_l2` |
| VSLA-P-2 | failed signature/subject/root/reproduction → L0, report still handled | `Verifier` pillars; `_verify_bundle` catches malformed bundles | `test_tampered_or_unsigned_statement_is_l0_and_case_still_runs` |
| VSLA-P-3 | DSSE receipt (receipt payload type) in every case, `not-attempted` when nothing ran | `vsla/dsse.py::make_receipt`, `_vsla_receipt` | same; `test_admission_deferral_issues_not_attempted_receipt_and_slow_lane` |
| VSLA-P-4 | re-execute at `subject[1]` in our sandbox with our classifier; `touchedSubject`; sandbox backend/isolation/digest and attempts in the receipt; status enum | `_reexecute` (`sandbox.checkout(revision)`), `_rerun`, `security/sandbox.py::run_classified` (`coverage` or `-X importtime`, method named in `touchedSubjectMethod`) | same; `test_reexecution_at_unavailable_revision_is_environment_error` |
| VSLA-P-5 | publish key, floors (incl. age gate), isolation class, admission limits, pinned countersigners | `server.py::policy_resource` (`vsla` block) | `test_get_attestation_and_ledger_tools` |
| VSLA-P-6 | countersign the outcome into the ledger at close; reasons on negatives | `_vsla_close`, `Ledger.append` | pipeline test; `test_rejected_and_unreproducible_outcomes_land_in_ledger_with_reasons` |
| VSLA-P-7 | rate limit / revoke per identity; lower the level, never drop | `security/ratelimit.py`, `Verifier` (I4 lowers to L1) | `test_submitted_statement_without_history_verifies_l1` |
| VSLA-P-8 | verify the environment quote against the root of trust, measurement allowlist, bound weights vs MBOM + attestation | `environment.py::verify_signed_quote`, `verify.py` N3 (`binding`, `meas_allowed`, `all_attested`) | `test_api_served_model_caps_environment_at_l2_and_attested_tee_reaches_l3`; reference examples in the interop test |
| VSLA-P-9 | never present claimed as verified | `report.vsla["submitted"]` keeps both; `get_attestation` returns both | `test_tampered_...` (claimed 3, verified 0) |
| VSLA-P-10 | platform's own adversarial review on a distinct model family; verdict digest and `distinctFamily` in the receipt | `_platform_review`, `Orchestrator(reviewer_provider=...)`, `inference.reviewer_provider/reviewer_model` | `test_submitted_patch_statement_is_reexecuted_reviewed_and_scoped` |
| VSLA-P-11 | isolation class named in receipt and policy; `vm` for production | `attest.py::sandbox_isolation` (`process` local, `vm` quome), receipt `sandbox`, policy `reexecution` | receipt assertions in the platform tests; **`process` is a development convenience and is labelled so** |
| VSLA-P-12 | admission control per identity and globally; defer without dropping | `Orchestrator._admit` (`reexec_per_identity_per_hour`, `reexec_concurrent`, `reexec_unknown_identities`), slow lane in `run_case` | `test_admission_deferral_issues_not_attempted_receipt_and_slow_lane` |
| VSLA-P-13 | no status/severity/lane/timing/timeline/test details/ledger entries for embargoed cases to third parties | `server.py::_may_see`, `_summary`, `list_reports`, `get_attestation`, `get_ledger`, `report_resource` | `test_ledger_and_case_metadata_are_scoped_while_embargoed` |
| VSLA-P-14 | store last (root, count) per finder; `ledger-fork` on mismatch | `Ledger.last_seen/remember`, `ledger_consistent`, `_vsla_receipt` | `test_ledger_fork_is_detected_and_recorded` |
| VSLA-P-15 | `accepted` = outcome accepted; `reproduced-unresolved` neutral; per-track entries | `_vsla_close` mapping | pipeline test; patch test (`{"finding": "accepted", "patch": "accepted"}`) |
| VSLA-P-16 | anchor receipts in a transparency log | `make_receipt(anchor=...)` carries one | **not implemented**: no log is written to |

## Verifier

| Id | Code | Test |
|---|---|---|
| VSLA-V-1 pinned keys | `vsla/keyring.py`, `verify.py::vsla_keyring` (reporters, platform, countersigners, providers, operators, roots; no `enclave:` keys) | `test_unverifiable_ledger_signatures_are_dropped`; L3 test (enclave key from the quote) |
| VSLA-V-2 min across pillars, first failing check, kind | `Pillar.finalize`, `Check.kind`, `VerificationResult` | all level assertions; CLI test checks kinds |
| VSLA-V-3 missing input = failed check; nothing self-reported stands in | every `run(..., False, "... not supplied")` branch; I4 without a ledger | `test_self_reported_history_fails_i4` |
| VSLA-V-4 the verifier re-executes itself at the subject revision | `_vsla_receipt`/`_reexecute` | `..._verified_l2`, `..._environment_error` |
| VSLA-V-5 count only pinned countersigners; verify each signature | `ledger.py::verified_ledger`, `rubric.py` | `test_unverifiable_ledger_signatures_are_dropped` |
| VSLA-V-6 expectations: harness digests, measurement allowlist | `Orchestrator._expectations` (own harness digest + `vsla.expectations_path`), `Verifier(expectations=...)` | N2/N3 assertions; `test_reference_examples_verify_under_qudisclose_verifier` |
