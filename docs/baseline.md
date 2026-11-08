# Baseline record (pre-change)

Captured before any feature work, so the differential test in Phase 15 has a
reference point.

| Item | Value |
| --- | --- |
| Date | 2026-11-08 |
| JDK | Eclipse Temurin 21.0.13+9 (LTS) |
| Maven | Apache Maven 3.9.9 |
| Node / npm | v22.20.0 / 10.9.3 |
| Python | 3.12.7 (used only by `tools/make_conn_log.py`) |
| Shell | Windows PowerShell 5.1 |
| `mvn test` | 127 tests, 0 failures, 0 errors, 0 skipped, BUILD SUCCESS in 37.5 s |
| `npm test` (web-client) | 35 tests in 12 files, all passing (after D-001) |
| `npm run typecheck` | see `docs/qa-report.md` |

The toolchain lives in `.tools/` (git-ignored). Invocation used for every
command in this project:

```powershell
$env:JAVA_HOME = "C:\Users\abdul\Downloads\project\threat-detection\.tools\jdk"
$env:PATH      = "$env:JAVA_HOME\bin;<repo>\.tools\maven\bin;<repo>\.tools\node;$env:PATH"
mvn -B -s .tools\settings.xml test          # repository pinned to .tools/m2
npm.cmd test                                # npm.ps1 is blocked by execution policy
```

## Defects found in the untouched baseline

**D-001: legacy `/portal/overview` URL never redirected (medium).**
`web-client/tests/routing.test.tsx` failed on a clean checkout: the assertion
`expected '/portal/overview' to be '/portal'` timed out.

Probing established two independent causes:

1. The `<Navigate>` for the legacy address was a child of the lazily imported
   `Shell`. When `Shell` suspends on its first mount, the effect that
   `Navigate` schedules never runs, so the URL stayed put. The legacy route was
   therefore broken in the real app too, not just in the test.
2. The test harness mounted `AppRoutes` without the `Suspense` boundary that
   `App`/`RouteStage` always supplies, so the first navigation towards a lazy
   route suspended with no fallback and the assertion could never settle.

Fixes: the legacy redirect is now a top-level route, outside the portal subtree
(`web-client/src/App.tsx`), and `tests/routing.test.tsx` mounts `AppRoutes`
inside `Suspense` exactly as the app does. Assertions were not changed or
weakened. Baseline after the fix: 35/35 web tests pass.

Note: this repository is not under version control here (the owner keeps it on
GitHub), so the baseline is recorded as a file rather than a commit, and the
per-phase commits required by the master prompt are instead logged in
`docs/change-log.md`.
