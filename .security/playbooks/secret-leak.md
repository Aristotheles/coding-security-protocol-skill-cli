# Secret leak response

An open hardcoded-secret finding triggers POL-005 and blocks merge/release.
The gate reports this playbook; it does not revoke credentials, send notifications,
or close the finding on a human's behalf. Use only obvious fake secrets in tests.

1. Revoke or rotate the exposed credential through its actual provider.
2. Determine exposure: source, Git history, logs, artifacts and remote systems.
3. Clean history when required, after coordinating with affected maintainers.
4. Check access logs and investigate misuse or abuse.
5. Notify the responsible owner through the incident response channel.
6. Document the incident without recording the secret itself.
7. Verify replacement secret handling and record rotation confirmation with
   confirmed_by and a UTC confirmed_at timestamp.
8. Close only after deterministic tests, relevant rescan, applicable runtime
   verification and policy checks, including required rotation confirmation.

Deleting a secret from the current source tree does not invalidate a credential
already exposed in Git history or remote systems. An AI cannot confirm rotation
or provide human approval. Test-fixture findings are not evidence of live exposure.
