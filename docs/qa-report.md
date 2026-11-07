# Field Station QA audit report

Date: 2026-11-07
Scope: local instance only, `http://localhost:18080`, started with `java -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 18080 --seed 42`.
Audit artifacts: `E:\project\qa-audit\`. No application source, config, data or tests were modified; `git status --short` in `E:\project\threat-detection` is clean.

## 1. Executive summary

The portal loads, authenticates, enforces the main role gates, streams alerts, runs the planner and produces reports. The audit still found release-blocking defects: the 2D map and WebGL-unavailable fallback crash with `FlatMap is not defined`, the 3D map has no working orbit controls, and simulated event time is frozen at `2026-01-01T00:00:00Z`, which breaks cooldowns, correlation windows and relative time. Automated client checks fail: `npm test` has 2 failed suites and `tsc --noEmit` reports many errors including the same `FlatMap` defect. Visual output does not match `docs/web-spec.md`: wrong UI font, dark shell instead of the specified sand main area, shadows, gradients and non-token colours. Security is acceptable for a local demo but not hardened: no security headers, weak session-cookie flags, no CSRF/origin enforcement, default credentials and a misleading `AES-256 enabled` claim.

## 2. Environment and automated checks

Versions observed: Java `17.0.12`, Maven `3.10.0`, Node `v26.13.0`, Chrome stable channel via Playwright, Javalin `6.3.0`, React `19.1.10`, Vite `8.3.5`, TypeScript `7.0.2`.

| Check | Result | Evidence |
|---|---|---|
| `mvn test` | PASS, 112 tests, 0 failures | `mvn-test.log` |
| `mvn package` | PASS with shade/module-info and duplicate-class warnings | `mvn-package.log` |
| `npm test` | FAIL, 8 files: 6 passed, 2 failed; 13 tests: 12 passed, 1 failed | `npm-test.log` |
| `npx tsc --noEmit` | FAIL, many strict errors | `tsc.log` |
| `npm run build` | PASS via `cmd /c`, Vite chunk warning over 500 kB | `npm-build-cmd.log`, `npm-build.log` |
| `npm audit` / `npm audit --omit=dev` | PASS, 0 vulnerabilities | `npm-audit-all.log`, `npm-audit.log` |
| Maven dependency vulnerability check | NOT AVAILABLE, `maven-dependency-plugin:check` goal does not exist | `mvn-dependency-check.log`, `mvn-dependency-tree.log` |
| No lint script | NOT AVAILABLE, `package.json` has only `dev`, `build`, `test` | `web-client/package.json` |

Client bundle: `index-DXbUjYkj.js` 1,410.18 kB minified, 405.24 kB gzip; CSS 71.31 kB, 13.90 kB gzip. Fonts emitted include Manrope, IBM Plex Sans/Mono and Newsreader.

## 3. Scorecard

| Area | Score | Justification and top evidence |
|---|---:|---|
| Functionality | 4 | Core pages and APIs work, but 2D/fallback crashes, no orbit controls, incidents do not live-update. Evidence: `webgl-fallback.cjs` output, `NetworkMap.tsx` grep for `OrbitControls`, `useStream.ts`. |
| Simulation and attack realism | 4 | Launch, multi-stage, planner and reports work; event time is frozen and reset leaves stale feed data. Evidence: `sim-checks.json`, `repeat-attack.json`, `TrafficSimulator.java:69-70`. |
| Data integrity | 4 | Stale alerts after reset, identical timestamps, alert count mismatch, correlation window meaningless. Evidence: `sim-checks.json`, `DetectionEngine.java:95-108`, `IncidentManager.java:50-56`. |
| Visual design and consistency | 3 | Dark shell, shadows, gradients, 8/10/14px radii and off-token colours violate spec. Evidence: `styles.css:65-126`, `styles.css:1890-1903`, `styles.css:2195-2206`. |
| Typography and colour | 3 | Portal UI font is Manrope, not IBM Plex Sans; status palette includes non-spec colours. Evidence: `styles.css:1-32`, `styles.css:83-88`, `docs/web-spec.md:16-24`. |
| Layout and responsiveness | 6 | No horizontal overflow at 360/768/1280/1920 in tested pages; mobile nav overlay works. Evidence: `visual-results.json`, `visual-mobile-nav-360.png`. |
| Motion and polish | 5 | Reduced-motion class applies and FPS was about 60 in 3D; deprecated THREE warnings and off-spec hover/shadow polish remain. Evidence: `reduced-motion.cjs` output, `perf.json`, `portal-pages-results.json`. |
| 3D map quality | 3 | Nodes, selection and labels exist, but orbit/zoom/pan is absent, 2D fallback crashes, context churn warnings appear. Evidence: `NetworkMap.tsx:3`, `NetworkMap.tsx:597-637`, `debug-map.cjs` output. |
| Performance | 6 | Fast load and stable 10-minute JS heap sample, but 1.4 MB bundle, chunk warning, unbounded client alert array and WebGL context warnings. Evidence: `perf.json`, `memory-run.json`, `npm-build.log`, `store.ts:99-105`. |
| Accessibility | 4 | Keyboard focus and labels mostly pass, Esc does not close popovers, NORMAL/HEALTHY badges have no text label, no axe/Lighthouse run. Evidence: `a11y.json`, `Shell.tsx:136-140`, `ui.tsx:48-63`. |
| Security and permissions | 5 | Role gates and logout invalidation verified; missing headers/cookie flags, no origin enforcement, weak/default credentials and misleading AES-256 claim. Evidence: `security-checks.json`, `api-checks-output.txt`, `Login.tsx:58`, `config.properties:17-22`. |
| Error and empty states | 6 | Many empty states are explicit and API errors map to 400/401/403; WebGL fallback produces a blank crashed page and 500/offline paths are unverified. Evidence: `portal-pages-results.json`, `webgl-disabled.png`, `flows-results.json`. |
| Code quality and tests | 3 | Maven tests pass, but client tests/typecheck fail, dead scene code, duplicate import and spec-violating characters remain. Evidence: `npm-test.log`, `tsc.log`, `SceneHost.tsx:54-67`, `Planner.tsx:8-9`. |
| Looks purpose-built, not generic AI output | 4 | There is a custom field-station concept, but the portal reads as a generic dark dashboard with shadows/gradients and off-spec styling. Evidence: `styles.css:1890-1903`, `styles.css:2195-2256`, `docs/web-spec.md:15-38`. |

Overall score: 43/100 (average of the 14 area scores, scaled to 100).

To reach 90+: fix the 2D/WebGL fallback and orbit controls, restore a system clock or explicitly document deterministic time while keeping cooldown/correlation correct, make reset clear the alert feed, bring the portal back to the spec design tokens and typography, get `npm test` and `tsc --noEmit` green, add security headers/cookie flags and honest auth copy, live-update incidents, cap client alerts, and close accessibility gaps.

## 4. Findings

| ID | Severity | Area/page | What is wrong | Steps to reproduce | Expected vs actual | Evidence | Suspected root cause | Recommended fix | Effort |
|---|---|---|---|---|---|---|---|---|---|
| F-01 | Critical | Map / all portal pages | 2D toggle and WebGL-unavailable fallback crash the app | Login as admin, open Overview, click `2D`; or launch Chrome with WebGL disabled and open `/portal` | Expected flat map or graceful fallback; actual `PAGEERROR FlatMap is not defined`, `.ops-side` count 0 | `debug-map.cjs` output, `webgl-fallback.cjs` output, `webgl-disabled.png`, `ui-overview-2d.png`, `NetworkMap.tsx:790-856`, `NetworkMap.tsx:888-889`, `tsc.log` `Cannot find name 'FlatMap'` | `FlatMap` is declared inside the `webglOk()` catch block, so it is not in module scope | Move `FlatMap` to module scope and add a jsdom/browser test for 2D mode and no-WebGL mode | S |
| F-02 | Critical | Simulation / detection / reports | Event timestamps are frozen at `2026-01-01T00:00:00Z`; time windows never advance | Run auto/attacks, inspect `/api/alerts`, `/api/incidents`, Reports | Expected live timestamps and working cooldown/correlation windows; actual identical timestamps, `relativeTime` returns `Earlier`, incident correlation window is meaningless | `sim-checks.json`, `repeat-attack.json`, `TrafficSimulator.java:69-70`, `TrafficSimulator.java:116-140`, `DetectionEngine.java:95-108`, `IncidentManager.java:50-56`, `memory-run.json` | Runtime facade uses `new TrafficSimulator(network, seed)`, which selects `Clock.fixed(...)` | Use `Clock.systemUTC()` for the web runtime and keep fixed clocks only in tests, or make the deterministic mode explicit and reset-safe | M |
| F-03 | Major | 3D map | No orbit, zoom or pan controls; camera focus code is inert | Inspect `NetworkMap.tsx` scene JSX and try to orbit the canvas | Expected OrbitControls with clamped polar angle and damping; actual `OrbitControls` is imported but never rendered, `controls.current` stays null | `NetworkMap.tsx:3`, `NetworkMap.tsx:579-637`, grep result: only import match for `OrbitControls`, `tsc.log` unused import | Controls ref is never attached to a rendered `<OrbitControls>` | Render `<OrbitControls ref={controls} ... />` inside the scene and test orbit/zoom/pan plus focus camera | M |
| F-04 | Major | Client tests / typecheck | `npm test` fails 2 suites and `tsc --noEmit` fails | Run `npm test` and `npx tsc --noEmit` in `web-client` | Expected green checks; actual parse error on duplicate `Asset`, ResizeObserver missing in jsdom, many strict TS errors | `npm-test.log`, `tsc.log`, `Planner.tsx:8-9`, `test-setup.ts` | Duplicate import, jsdom lacks ResizeObserver, strict `noUnusedLocals` exposes dead code, CSS side-effect imports lack declarations | Remove duplicate import, add ResizeObserver mock or mock `NetworkMap` in tests, fix or remove dead code, add CSS module declaration | M |
| F-05 | Major | Simulation reset / Alerts / bell | Reset clears incidents/state but not the alert feed | Login, create alerts, `POST /api/sim/reset`, then `GET /api/alerts` and reload portal | Expected empty feed after reset; actual `/api/state` shows 0 alerts/incidents while `/api/alerts` still returns 20 stale alerts | `sim-checks.json` steps `state after reset`, `alerts after reset`, `StreamBroadcaster.java:21-29`, `IncidentResponseFacade.java:107-114`, `ApiRoutes.java:360-376` | `StreamBroadcaster.recent` has no clear/reset path and reset only broadcasts state/network | Add a broadcaster reset/clear on sim reset and refresh client alerts after reset | S |
| F-06 | Major | Visual design / all pages | Portal does not match `docs/web-spec.md` design tokens | Compare `styles.css` and screenshots to spec | Expected forest sidebar + sand main, IBM Plex Sans, radius 0/4, no shadows/gradients; actual dark `#07110b` shell, Manrope UI font, shadows, gradients, 8/10/14px radii, off-token colours | `styles.css:65-126`, `styles.css:1890-1903`, `styles.css:2195-2206`, `styles.css:2286-2291`, `docs/web-spec.md:15-38`, `visual-overview-1280.png` | Portal theme was implemented with a separate dark token set and utility styles | Reconcile `styles.css` to spec tokens, remove banned shadows/gradients/radii, set `--font-ui` to IBM Plex Sans | L |
| F-07 | Major | Status badges / Hosts / accessibility | NORMAL and HEALTHY badges render only a coloured dot, no text label | Open Hosts or Overview with healthy assets | Expected every status has a text label; actual `StatusBadge` returns `null` label for NORMAL/HEALTHY, so status column looks empty | `ui.tsx:48-63`, `portal-pages-results.json` hosts text rows show risk then next host with no status word, `docs/web-spec.md:23-24` | `quiet` mode suppresses the label for normal states | Always render the status text; keep colour as reinforcement only | S |
| F-08 | Major | Map architecture / performance | `SceneHost` never activates and each page mounts its own map, causing WebGL context churn | Navigate Overview -> Alerts -> Attack lab -> Planner in one session and watch console | Expected one shared scene/slot per spec; actual `SceneHost` queries `[data-map-slot]` but no element sets it, while pages render separate `NetworkMap`/`NetworkStage` canvases | `SceneHost.tsx:49-67`, `ui.tsx:68-83`, grep: no `data-map-slot` outside `SceneHost.tsx`, `portal-pages-results.json` overview has 52 `Too many active WebGL contexts` warnings | Shared scene slot was never wired into `MapPanel`; per-page maps remained | Either wire `data-map-slot` into `MapPanel` and use `SceneHost`, or remove `SceneHost` and explicitly manage one canvas per page with disposal | M |
| F-09 | Major | Incidents / Reports / nav badges | Incident data is loaded once and never refreshed by SSE | Start sim, generate an incident while portal is open, stay on Incidents/Reports | Expected incidents and badges update live; actual SSE handles only `alert`, `network`, `state`; incidents load once in `Shell` | `useStream.ts:17-28`, `Shell.tsx:22-26`, `store.ts` incidents setters | No incident event or periodic refetch exists | Add incident updates to state broadcast/SSE or refetch incidents on relevant state changes | M |
| F-10 | Medium | Security / API | Missing security headers and weak session cookie; state-changing POSTs do not check Origin/CSRF | Inspect `GET /` and `POST /api/login` headers; POST with `Origin: https://evil.example` and `Content-Type: text/plain` | Expected CSP/X-Frame-Options/Referrer-Policy, `HttpOnly; SameSite` cookie, origin or CSRF checks; actual only `Cache-Control`, `JSESSIONID` has only `Path=/`, evil-origin POST returns 200 | `security-checks.json`, `WebServer.java:37-53`, `ApiRoutes.java:143-176`, `ApiRoutes.java:360-376` | No security header filter, no CSRF token, Jetty session cookie flags not configured | Add headers, set cookie flags, reject cross-site state changes or require a CSRF token for non-GET API calls | M |
| F-11 | Medium | Attack lab / API validation | API accepts same source and target attack | `POST /api/attacks` with `src` and `dst` both `srv-web-1` | Expected 400 like the client `launchReady`; actual 200 and events queued | `security-checks.json` `POST attack same host`, `api-checks-output.txt` line 21, `ApiRoutes.java:160-175`, `launch.ts:1-3` | Backend validates only that assets exist, not that they differ | Add `src == dst` rejection in `ApiRoutes.attack` and a negative API test | S |
| F-12 | Medium | Alerts / simulated-data clarity | Backend-simulated detector alerts are not consistently tagged as simulated | Run auto/attacks and inspect Overview/Alerts rows | Expected clear SIMULATION marking for all synthetic traffic; actual only client scenario alerts (`sim-` id or `Field station` detector) get the pill, while `PortScanDetector` alerts do not | `Overview.tsx:226-241`, `sim-checks.json` alerts have `detectorName: PortScanDetector`, `portal-pages-results.json` overview text | Simulation tag is inferred from alert id/detector name, not from event provenance | Propagate a simulation marker from `TrafficSimulator`/event metadata to alerts and render it everywhere | M |
| F-13 | Medium | Client state / long sessions | Alert store is unbounded; display cap exists but is not applied to the store or Alerts page | Keep SSE open during a long auto/scenario run and inspect `useApp.alerts.length` | Expected bounded feed around 500; actual `pushAlert` appends forever and `AlertsPage` filters the full array | `store.ts:99-105`, `alerts.ts:12-22`, `AlertFeed.tsx:53`, `Alerts.tsx:19-22` | `capAlerts` is only used in `AlertFeed`, not in `pushAlert` or `AlertsPage` | Apply `capAlerts` inside `pushAlert`/`setAlerts` and reuse capped data in Alerts | S |
| F-14 | Medium | Shell popovers / keyboard | Escape does not close bell, user or simulation menus; menus have no focus trap | Open bell popover, press Escape; open user menu, press Escape; open sim menu, press Escape | Expected Esc closes popovers; actual only selected node/sidebar overlay are cleared | `a11y.json` FAIL `Esc closes alert popover`, `Shell.tsx:132-147`, `Control.tsx:48-83` | Global key handler does not call `setBellOpen(false)`, `setUserOpen(false)` or sim menu close | Close all popovers on Escape and add focus return/arrow-key handling for menus | S |
| F-15 | Medium | Auth / login copy | Default credentials are weak/plaintext-friendly and login claims `AES-256 enabled` with no evidence | Read `config.properties`, `User.checkPassword`, `Login.tsx` | Expected hashed salted credentials and honest transport/security copy; actual defaults `admin/admin`, `analyst/analyst`, `viewer/viewer`, plaintext or unsalted SHA-256 accepted, UI says AES-256 enabled | `config.properties:17-22`, `User.java:17-32`, `IncidentResponseFacade.java:74-79`, `Login.tsx:58`, `security-checks.json` login 200 | Demo auth was not hardened and copy overstates protection | Use salted password hashes or an auth library, remove default creds for non-demo, change login copy to match reality | M |
| F-16 | Minor | UI copy | Em dash character `U+2014` appears in UI text, violating spec | Search client source for the U+2014 character | Expected no em dash in UI; actual `Planner.tsx` and `Reports.tsx` contain it | `Planner.tsx:228`, `Reports.tsx:98,141,142,145,159,168`, `docs/web-spec.md:30` | Copy used em dash placeholders/separators | Replace with hyphen, comma or colon | S |
| F-17 | Minor | Host detail copy | Host detail says plan payload does not name a host, but API does provide host fields | Open a host detail after running planner | Expected accurate guidance; actual note contradicts `taskDetails.hostId/hostName` used by Planner | `Hosts.tsx:56`, `ApiRoutes.java:313-319`, `types.ts:31`, `Planner.tsx:133-138` | Stale copy from before `taskDetails` existed | Update host detail copy or link tasks to host detail | S |
| F-18 | Minor | Build / dependencies | Build emits warnings and client has dead/unused code | Review `mvn-package.log`, `npm-build.log`, `tsc.log` | Expected clean build; actual shade/module-info/duplicate warnings, chunk >500 kB, THREE deprecation warnings, many unused declarations | `mvn-package.log`, `npm-build.log`, `tsc.log`, `portal-pages-results.json` | Shade plugin overlaps and client dead code/large single bundle | Review shade minimizes, code-split routes/three, remove dead code, upgrade THREE usage | M |
| F-19 | Minor | API state / badges | `/api/state.alertCount` counts incident alerts, not the alert feed | Compare `GET /api/state` with `GET /api/alerts` after a run | Expected one clear alert count; actual state showed `alertCount:1` while feed returned 20 alerts | `sim-checks.json`, `ApiRoutes.java:425-446`, `StreamBroadcaster.java:73-78` | `buildState` sums incident alerts only | Rename field or return feed count consistently and document semantics | S |

## 5. What works well

- Login/logout and role gates are consistent between UI and API: unauthenticated `/portal` redirects to `/login`, viewer UI hides restricted nav and direct API calls return 403.
- API validation is mostly sane: malformed JSON 400, bad credentials 401, bad planner input 400, logout invalidates the session.
- Core pages render without page errors in the tested 3D path: Overview, Attack lab, Alerts, Incidents, Hosts, Host detail, Planner, Reports, Control, Admin.
- Attack lab and planner flows work end to end: launch validation, multi-stage POST sequence, planner run, exclusion stale badge, details/map toggle, report raw text and export menu.
- `mvn test` is strong: 112 backend tests pass.
- `npm audit` reports 0 vulnerabilities.
- Reduced-motion mode is applied (`shell reduced-motion`) and a 10-minute browser JS heap sample did not show a clear monotonic leak.
- Visual screenshots show no document-level horizontal overflow at 360, 768, 1280 and 1920 for the tested pages.

## 6. Prioritised fix plan

Batch 1 - Blockers and Criticals
1. F-01: move `FlatMap` to module scope; add tests for 2D toggle and WebGL-unavailable fallback.
2. F-02: switch runtime simulation to `Clock.systemUTC()` or an explicit deterministic mode that still advances time; verify cooldowns, correlation windows and relative time.
3. F-05: clear `StreamBroadcaster.recent` on reset and refresh client alerts.
4. F-04: remove duplicate `Asset` import, fix test setup and get `npm test`/`tsc --noEmit` green enough to catch F-01/F-03 regressions.

Batch 2 - Majors
1. F-03: render and configure `OrbitControls`; verify orbit/zoom/pan, clamped polar angle, damping and focus camera.
2. F-06/F-07/F-16: restore spec typography/colour/radius/no-shadow rules, always show status text, remove em dashes.
3. F-08: resolve the dead `SceneHost`/per-page map duplication and WebGL context churn.
4. F-09: live-update incidents in shell state or refetch on state changes.
5. F-10/F-15: add security headers/cookie flags/origin checks and honest auth credential handling/copy.
6. F-11/F-12/F-13/F-14/F-19: API same-host validation, simulation tagging, alert cap, Esc/menu keyboard handling, state count semantics.

Batch 3 - Minors and polish
1. F-17: fix host detail copy.
2. F-18: reduce build warnings, split the bundle, remove dead code and unused dependencies.
3. Re-run visual review at all required widths after the design-token pass.

## 7. Regression risk list and tests to add

- Fixing `FlatMap` scope could change 2D rendering; add a browser test that toggles 2D on Overview/Attack lab/Planner and a no-WebGL context test.
- Changing the clock affects every detector window, cooldown, incident correlation and report timestamp; add backend tests with `Clock.fixed` for determinism and `Clock.systemUTC` for runtime ordering.
- Clearing broadcaster alerts on reset could surprise clients that expect history; decide whether reset means full feed clear and test SSE `alert`/`network`/`state` sequence.
- Restyling to spec tokens can break selectors and screenshots; add visual regression screenshots at 360/768/1280/1920.
- Adding OrbitControls can conflict with click-to-select and empty-space deselect; test raycast select, empty click, Esc clear and camera focus.
- Security header/cookie changes can break SSE or downloads; test `/api/stream`, report export and login under the new flags.
- Capping alerts can drop rows users expect; test `capAlerts`, duplicate grouping and Alerts filters at 500+ alerts.
- Missing high-risk tests to add: simulation scheduler/auto loop, camera controls, alert grouping/cap, planner diff/history, SSE reconnect, permission matrix for every endpoint, reset semantics.

## 8. Not verified

- axe-core and Lighthouse were not run; no axe/Lighthouse dependency was installed in the audit environment. Manual keyboard/focus/label checks were run instead (`a11y.json`).
- Backend stop mid-session, offline mode, slow-network throttling, multiple tabs, session expiry timing and forced 500/timeouts were not fully exercised.
- Deterministic seed behaviour across two fresh server instances was not compared; only the running `--seed 42` instance was observed.
- 2D map frame rate is not measurable because 2D mode crashes (F-01); WebGL-unavailable fallback crashes for the same reason.
- CPU usage, long tasks and CLS were not instrumented; only navigation timing, resource transfer, canvas count, rAF FPS and JS heap samples were collected.
- Viewports 2560 px and short height 600 px were not captured; tested widths were 360, 768, 1280, 1920 plus a 640x400 zoom check.
- Touch/mobile gestures, hover labels in 3D, orbit/zoom/pan behaviour and map keyboard alternatives could not be fully verified because orbit controls are absent and 2D crashes.
- Maven OWASP `dependency-check` was unavailable (`mvn-dependency-check.log`); only `dependency:tree` and `npm audit` were run.
- Production deployment, real telemetry separation and any non-local data were intentionally not touched.

## 9. Suggested next audit

After fixes, re-run: `npm test`, `npx tsc --noEmit`, `npm run build`, `mvn clean test`, `npm audit`, API permission matrix, browser flows for every page, 2D toggle and WebGL-disabled fallback, orbit/zoom/pan and focus camera, full auto scenario for at least three cycles, stop/reset mid-scenario, stale-feed check after reset, incident live-update check, security header/cookie/CSRF checks, axe/Lighthouse on all pages, viewports 360/768/1280/1920/2560 and short viewport, reduced-motion, disconnect/reconnect and a longer memory/CPU/CLS run.
