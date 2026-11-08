# QA Report: Network Threat Detection & Cyber Security Monitoring System (threat-detection)

Status: This report records what was run and what was not. No independent review has been done; all findings and measurements come from the same assisted session that wrote the code.
Audited: 2026-11-07 for the base system, with a final gate on 2026-11-08 covering flow telemetry, the durable store, security hardening, Zeek import, threat intel, NDR detectors, the alert quality gate, the pure Java flow model, SIEM correlation, containment, notifications, forensics, compliance and benchmarks, then a completion pass on the same day over the items that gate left open.
Auditor: Qoder (assisted QA session).
Scope: Maven backend (23 packages, 141 compiled sources, 259 tests in 46 classes), React/Vite client (15 pages, 15 test files, 66 tests), live HTTP API on the packaged jar, offline Zeek import, benchmark mode, static architecture and design conformance audit.

---

## Part A: base system audit (2026-11-07)

## 1. Environment and commands actually executed

| Item | Value |
| --- | --- |
| OS | Windows 25H2, PowerShell 5.1 |
| Java | 17.0.12 (Temurin) |
| Maven | 3.10.0 |
| Node | v26.13.0 |
| npm | invoked as `E:\nodejs\npm.cmd` (npm.ps1 blocked by execution policy) |
| Server under test | `java -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 18080` |

| Command | Result |
| --- | --- |
| `mvn -q clean test` | BUILD SUCCESS, Tests run: 127, Failures: 0, Errors: 0, Skipped: 0 |
| `mvn -q package -DskipTests` | BUILD SUCCESS (the shade plugin emits overlapping `META-INF/LICENSE` and `NOTICE` warnings only) |
| `npm test -- --run` | 12 files, 35 tests, all passed |
| `npx tsc --noEmit` | exit 0, no type errors |
| `npm run build` | exit 0, no chunk size warning, output to `src/main/resources/web/` |
| `npm audit --omit=dev` | 0 vulnerabilities |

Bundle after code splitting: `index-*.js` 31.33 kB, `react-*.js` 227.27 kB, `motion-*.js` 131.45 kB, `three-*.js` 949.52 kB (252.52 kB gzip, lazy, portal routes only), one chunk per route, and `index-*.css` 72.7 kB. The stylesheet carries 810 rules from a 2,333 line source.

---

## 2. Findings

Severity: Critical = blocks use, High = user visible breakage or security exposure, Medium = incorrect behaviour or spec violation, Low = hygiene.

| ID | Severity | Area | Status | Title |
| --- | --- | --- | --- | --- |
| F-01 | Critical | Build | Fixed | Backend did not compile (Dtos stub plus incidents mapping) |
| F-02 | High | Process | Open (owner deferred: git excluded) | No version control, no CI gate |
| F-03 | Medium | API | Resolved | Unknown `/api/*` returned 401 instead of 404 |
| F-04 | Medium | API / detection | Resolved | `simulated` flag wrong for SignatureDetector alerts |
| F-05 | Medium | API / coupling | Resolved | `simulated` inferred from detector name strings |
| F-06 | High | Security | Resolved | Unsalted SHA-256 passwords, default demo accounts, no login throttling |
| F-07 | Low | Security | Resolved | Cookie had no `Secure` or `Max-Age`, no CSRF token (Origin check only) |
| F-08 | Medium | Security | Resolved | Request body content type not enforced |
| F-09 | Low | API | Resolved | Inconsistent `limit` validation on `/api/alerts` |
| F-10 | Medium | Code spec | Resolved | Magic numbers in web, detection and simulation layers |
| F-11 | High | Frontend perf | Resolved | Two map scenes mounted at once, forcing the 2D fallback |
| F-12 | High | Design spec | Resolved (owner directed palette) | Dark theme, shadows, gradients, non spec radii, wrong font |
| F-13 | Medium | UX / routing | Resolved | `/portal/overview` rendered blank |
| F-14 | Medium | Spec | Resolved | Public landing called `/api/state` and logged a 401 |
| F-15 | Medium | Frontend | Resolved | Duplicate React keys in hero traffic lines |
| F-16 | Medium | Perf | Resolved | 1.43 MB single JS chunk, no code splitting |
| F-17 | Low | Tooling | Resolved | No lint or typecheck script, runtime deps in `dependencies` |
| F-18 | Low | Architecture | Accepted, documented | Client duplicates backend authorization rules |
| F-19 | Low | UX | Resolved | Admin page was a placeholder |
| F-20 | Low | API / SSE | Resolved | SSE connect sent no initial snapshot |
| F-21 | Low | Accessibility | Resolved | No focus trap in overlays, focus ring contrast unverified |
| F-22 | Medium | Tests | Resolved | No automated coverage for the failure modes found here |
| F-23 | Medium | Frontend | Resolved | Mojibake in landing copy (copyright sign, star and arrow glyphs) |

### 2.1 The blocking defect

The repository did not compile on the first run. `web/Dtos.java` carried an IDE stub after an "implement methods" action:

```java
public IncidentDto(String id2, String name, String string, String sourceIp2, int size) {
    //TODO Auto-generated constructor stub
}
```

A record cannot declare a non canonical constructor with a mismatched parameter list, so the canonical constructor was rejected and the record type became unresolved at every use site. In the same area, `ApiRoutes.incidentsJson()` was written against an older DTO shape (`id, name, sourceIp, size`) and omitted the `alerts` array the client type requires. Removing the stub and rewriting the mapping fixed both; `GET /api/incidents` now returns rows with a populated `alerts` array and the page renders 11 rows.

Two breakages of this class reached the working tree because there is no git repository and no CI gate. A single `mvn -q clean test` on a pre-commit hook would have blocked both.

---

## 3. What changed

### 3.1 Backend

| Finding | Change | Evidence |
| --- | --- | --- |
| F-03 | `/api/*` is a closed route set; anything else falls through to a 404 handler | `GET /api/unknown` is 404 anonymous and signed in |
| F-04, F-05 | `simulated` is domain data: `NetworkEvent` carries it, `Alert` stores it, `DetectionEngine` copies it from the triggering event, `AlertDto` exposes it. The detector-name heuristic is deleted | An injected DoS flood raised by `SignatureDetector` reports `simulated = true`, the exact case that was wrong before |
| F-06 | PBKDF2WithHmacSHA256, 210000 iterations, 16 byte random salt, stored as `pbkdf2$iterations$salt$hash`. `LoginThrottle` allows 5 failures per 300 s per username and address, then answers 429 with `Retry-After` | 5 bad logins are 401 each, the 6th is 429 with `Retry-After: 300` |
| F-07 | Double submit CSRF: a `csrf` cookie is issued on login and on the first `/api/state`, `X-CSRF-Token` is required on mutating verbs and compared with `MessageDigest.isEqual`. The cookie carries `Path=/`, `Max-Age` equal to the session timeout, `SameSite=Strict`, and `Secure` when `auth.session.secureCookie` is set. The Origin check remains as a second gate | `POST /api/sim/start` without the header is 403, with it 200 |
| F-08 | Non JSON request bodies are rejected before parsing | `POST /api/attacks` with `text/plain` is 415 |
| F-09 | `limit` is validated before use | `GET /api/alerts?limit=-1` is 400 |
| F-10 | Simulation magic numbers moved into `config.properties` | `/api/config` returns the configured values |
| F-20 | `StreamBroadcaster` sends a `hello` frame with the current snapshot on subscribe | The SSE probe receives `hello` first |

### 3.2 Frontend

| Finding | Change |
| --- | --- |
| F-11 | `SceneHost` deleted. `NetworkStage` is mounted once per page. `webglOk()` caches its probe and releases the context, and `NetworkMap` no longer tears the renderer down by hand, so the fiber runtime is the only owner of the lifecycle. One canvas per page, no context warnings |
| F-12 | Palette rebuilt around the owner's direction (section 3.4), tokens consolidated in `:root`, radius 4 px, shadows removed, IBM Plex only. The 3D scene asks for PCF shadows because three r186 removed `PCFSoftShadowMap` |
| F-13 | `/portal/overview` redirects to `/portal`; unknown `/portal/*` renders a Not found page with a way back |
| F-14 | The landing page no longer calls `/api/state` |
| F-15 | Hero traffic keys derive from stable ids |
| F-16 | Every route is `React.lazy` under one `Suspense`; `manualChunks` splits three, motion and react |
| F-17 | Scripts: `dev`, `build`, `preview`, `test`, `typecheck`. Build tooling moved to `devDependencies` |
| F-19 | Admin reads the admin-only `/api/config` and renders detector thresholds, session details and the account table |
| F-21 | Alert and account popovers are `role="dialog"` with `aria-modal`, take focus on open, wrap Tab inside, and return focus to the trigger. Login autofocuses the username field and reports the 429 throttle state |
| F-23 | The mojibake from an earlier edit is replaced with ASCII text plus explicit `\u00A9` and `\u2192` escapes, and the built bundle is scanned for double encoded sequences |

### 3.3 Removed

- `cp.txt` (stray classpath dump), `qa-audit\` (audit logs and screenshots) and `target/ntd-verify*.ps1` (throwaway scripts).
- `web-client/src/sampleNet.ts` and the components `AlertFeed`, `Count`, `DecryptText`, `FieldFigure`, `HeroNetwork`, `HeroOrb`, `ParticleSphere`: zero imports, zero mentions in docs.
- `web-client/src/fonts/Manrope-400/500/600/700.woff2`, replaced by IBM Plex.
- `web-client/tests/scene-mount.test.tsx`, replaced by `tests/routing.test.tsx`.
- CSS token names that described the old palette: `--sand`, `--sand-on-forest`, `--accent-amber`, `--bg-color`.

No file referenced by the build, the jar or the docs was removed.

### 3.4 Palette tokens (current)

`web-client/src/styles.css` opens with one commented `:root` block. Page rules keep their old names as aliases (`--text`, `--ink`, `--ink-muted`, `--ink-faint`, `--muted-on-forest`, `--ink-on-lime`) so roughly 200 declarations did not have to move.

| Token | Value | Role |
| --- | --- | --- |
| `--text-heading` | `#E8DCC4` | headings, primary text, the 3D label colour |
| `--text-body` | `#C9C2AC` | paragraphs, ledes, notes, deltas |
| `--text-label` | `#A7B8AC` | secondary text, mono labels, table captions |
| `--text-muted` | `#7E9488` | muted text, placeholders, footer lines |
| `--accent-gold` | `#D9A05B` | emphasis: headline word, sparklines, highlighted figures, hero wireframe |
| `--accent-lime` | `#B7F36B` | live data only: connection dot, unread dot, avatar ring, meters, chart markers |
| `--action-gold` | `#D9A93A` | every filled control and every focus ring |
| `--action-gold-hover` | `#E4B44E` | filled control on hover |
| `--action-gold-soft` | `rgba(217, 169, 58, 0.14)` | active navigation tint |
| `--action-ink` | `#17120A` | text on a gold fill, never pure black |
| `--accent-ink` | `#0C1A05` | text on a lime fill |

Surfaces are `--bg #050A07`, `--surface-1 #0D1A12`, `--surface-2 #12241A`, `--surface-3 #1A2E22`, `--border #1B2B22`, `--border-strong #2A4436`. Status colours never use gold: `--critical #FF6B6B`, `--warn #F2C94C`, `--ok #5FCB8B`, `--info #6FA8FF`, `--isolated #7D8FA3`.

The four cool off-whites (`#E6EEE9`, `#9FB0A6`, `#6B7D73`, `#A9BAB0`) and the stray `rgba(230, 238, 233, ...)` tints are gone from the client sources. `#F3F6F4` never existed in this codebase.

### 3.5 The map scene now has a floor

The topology camera sits about 75 world units from the origin. The old `FadeGrid` drew a 64 by 64 plane in `MAP.grid` (`#1b3025`) on a background of `MAP.bg` (`#07100b`), a difference of a few percent, so the plane dissolved into the page. It is replaced by `MapGround`:

| Layer | Value |
| --- | --- |
| Plate fill | `MAP.ground` `#10251a`, `circleGeometry` radius 30, opacity 0.95 |
| Grid | shader, 60 minor cells and 15 major cells across the plate |
| Grid alpha | `minor * 0.16 + major * 0.5`, multiplied by a radial fade `1 - smoothstep(0.45, 0.98, r)` |
| Rim | `ringGeometry` 29.5 to 30, `MAP.groundRim` `#7d9c88`, opacity 0.7 |
| Elevation | the group sits at y = -0.35, below the node ring at y = 0.04 |

The radial fade stops the grid before the rim, so the plate edge is a clean line rather than a hard cut in the middle of a cell. `MAP.ground`, `MAP.groundLine` and `MAP.groundRim` live in `src/components/map/MapConfig.ts`; `MAP.bg` and `MAP.grid` are unchanged so the cleared canvas still matches the page.

The same scene had a second, independent defect. `<fog args={[SCENE_COLOR, 20, 80]}>` started fogging at 20 units while the camera sits about 75 units out, so every lit `meshStandardMaterial` body was already replaced by the fog colour. drei's `Line` uses `LineMaterial`, which ignores fog, which is why the links stayed crisp while the node bodies vanished. The range is now `[70, 170]`, past the outer node ring.

### 3.6 The flat map

Three defects sat in the flat map.

1. **No `viewBox`.** `placeNodes` puts hosts on 48 unit rings, so coordinates run from about -25 to 49. With no `viewBox` one unit became one pixel and the graph rendered as a small cluster in the top left corner of a 520 pixel panel. The map now derives a padded, square `viewBox` from the placed node bounds, uses `preserveAspectRatio="xMidYMid meet"`, and was rescaled for that space: radii 2.6 / 2.1 / 1.5, ring +0.7, selection +1.1, link strokes 0.55 and 0.22, marker 3 by 2.2. Three guide rings at r = 8, 16 and 22 make the layout legible.
2. **Invalid SVG paint values.** The hex strings were built without their leading hash, so `MAP.nodeHealthy.toString(16)` produced `a9c4b3`. An invalid `fill` or `stroke` falls back to black, so the nodes and links were black blobs on a black field. A local `hex()` helper prefixes the hash for every colour the flat map emits.
3. **No ground of its own.** The 2D view now draws the same three layers as the 3D scene with SVG primitives: a `radialGradient` plate (`#0F2218` at 0.98, `#0B1A11` at 0.9, `#07100B` at 0.55), a 6 unit grid `pattern` in `.flat-grid-line` at 0.18, and a `.flat-ground-rim` circle at 0.3. Padding grew from 11 to 13 and the minimum view size from 24 to 68 so the plate always fits inside the frame. Colours live in CSS classes, not presentation attributes, because `var()` is not valid inside an SVG attribute.

The pass also added per node `<title>` tooltips, `role="button"` with `tabIndex` and Enter or Space activation, a gold focus ring, and a `role="group"` label on the SVG. The host panel risk chart had the same class of problem in reverse: it drew a `#1f3d2b` polyline with no `viewBox`, and a dead global `.spark` rule fixed its width at 96 pixels. It now uses the `.spark` class, takes the gold stroke from the token block, and carries its own `viewBox`.

### 3.7 The flat map escaped its card

`.flat-map` is now `position: absolute; inset: 0` inside a stage that is a fixed 520 pixels, but that alone was not the fix. The measurement that mattered was the computed `min-height`: `586.95px`, exactly 65 percent of the 902.98 pixel viewport. `styles.css` carried

```css
.shell .map-slot, .shell .map-frame, .shell .map-stage, .shell .flat-map { background: var(--bg); min-height: 65vh; }
```

at specificity (0,2,0), which outranked `.flat-map { min-height: 0 }` at (0,1,0). The SVG was therefore clamped to a viewport fraction inside the fixed stage, running 67 pixels past the stage and 50 pixels past the panel border, and the card border cut the bottom of the plate and the bottom row of nodes. The `65vh` is gone; the rule now carries only the background.

### 3.8 Controls are gold

Filled controls take `--action-gold` `#D9A93A` with `--action-ink` `#17120A`; hover takes `--action-gold-hover` `#E4B44E`. No pure black is involved. The rule covers `:focus-visible`, the search and login focus rings, the hero tab underline, link and footer hovers (using the softer `--accent-gold`), the sidebar active marker, the floating `.nav-marker` bar, the active navigation tint, the `3D | 2D | Rotate` toggle, and every filled button on the landing page and in the portal.

The map toggle needed two edits. `.topo-toggle button.on` was changed first and the selected button still computed to `rgb(26, 46, 34)` with cream text, because `.shell .topo-toggle button.on` appears later in the file at higher specificity and reset the fill to `--surface-3`. Both now resolve to `rgb(217, 169, 58)` with `rgb(23, 18, 10)` text.

### 3.9 Product name and auto-rotate

- `web-client/src/brand.ts` is the single source of the product name, read by the sidebar, the login panel, the landing bar and footer, the document title and the README. `.brand-name` wraps with a 12.5 px size and a 200 px cap, `.vesper-brand` wraps at 30ch, and the login label gained a right inset, so the long name does not clip or scroll at 1440 px.
- `src/autoRotate.ts` holds the whole rotation decision: `shouldAutoRotate({ enabled, reducedMotion, dragging, idleMs, hasSelection, attackActive })`, plus `AUTO_ROTATE_SPEED = 0.6` (about one turn per 100 seconds) and `AUTO_ROTATE_RESUME_MS = 3000`. A hovered host, a selected host and a live attack each hold the camera still. With `prefers-reduced-motion` the button is off, disabled and explains why. The toolbar renders `3D | 2D | Rotate`, and Rotate exists only in 3D.
- Three dead comparisons against a detector name that no longer exists on the server were removed; the simulation badge now reads the typed `simulated` field, or the `sim-` id prefix for rows created before the contract change.

---

## 4. Contrast, measured

Relative luminance and ratios use the WCAG 2.x formula, and the pairs are pinned in a test.

| Foreground | on `#050A07` | on `#0D1A12` | AA 4.5:1 | AAA 7:1 |
| --- | --- | --- | --- | --- |
| heading `#E8DCC4` | 14.69:1 | 13.18:1 | pass | pass |
| body `#C9C2AC` | 11.20:1 | 10.05:1 | pass | pass |
| label `#A7B8AC` | 9.59:1 | 8.60:1 | pass | pass |
| muted `#7E9488` | 6.15:1 | 5.52:1 | pass | fail |
| gold `#D9A05B` | 8.67:1 | 7.78:1 | pass | pass |
| ink `#0C1A05` on lime `#B7F36B` | 13.77:1 | n/a | pass | pass |
| ink `#17120A` on action gold `#D9A93A` | 8.59:1 | n/a | pass | pass |

Every pair clears AA. Muted text is the only token that stops at AA, which is the intended role for placeholders and footnotes. Focus rings measure 9.20:1 on the base and 8.25:1 on a panel; the gold hover fill measures 9.70:1.

---

## 5. Regression tests

Backend, 127 tests, up from 117:

- `WebServerTest`: unknown API path returns 404; POST without the CSRF header is rejected; the CSRF cookie carries `SameSite=Strict` and `Max-Age`; non JSON bodies get 415; five failed logins are throttled with `Retry-After`; an injected attack is flagged simulated; the stream opens with `hello`; `/api/config` is admin only; `limit=-1` is rejected. The shared `call()` helper replays the CSRF cookie, and the CSP assertions cover `object-src`, `frame-ancestors` and `base-uri`.
- `NetworkEventTest`: the field list includes `simulated`, plus a provenance test that pins the default and the explicit constructor.
- `IncidentResponseEndToEndTest` and `MitigationPlanningTest` cover the response workflow and planning paths.

Client, 35 tests in 12 files:

- `tests/theme.test.ts`: no white text under `src` (property aware, so `background: #fff` stays legal); the palette tokens exist with the exact values; none of the old cool off-whites survives; every WCAG pair is at least 4.5:1; and no rule that targets `.flat-map` sets a viewport unit `min-height`. The last case was checked against a synthetic rule reproducing the original bug before it was trusted.
- `tests/autoRotate.test.ts` (9 cases) and `tests/rotateControl.test.tsx` (3 cases): the rotation decision, the 3 second resume boundary, reduced motion, hover and selection pauses, and the toolbar behaviour in both views.
- `tests/routing.test.tsx`: `/portal/overview` redirects to `/portal`, an unknown portal path renders Not found, and the landing page renders outside the shell.
- `tests/csrf.test.ts`: a POST picks up `X-CSRF-Token` from the cookie and a GET does not send it.
- Existing suites cover alerts, layout, motion, permissions, scene and session.

Uncovered on purpose: no browser automation and no Lighthouse or axe run (section 8).

---

## 6. Verification evidence

Live API matrix against the packaged jar:

```
GET  /api/state (anonymous)        = 401
GET  /api/unknown (anonymous)      = 404
POST /api/login wrong password     = 401
POST /api/login admin              = 200
csrf cookie issued                 = yes
GET  /api/unknown (signed in)      = 404
POST /api/sim/start without token  = 403
POST /api/sim/start with token     = 200
GET  /api/state (signed in)        = 200
POST /api/attacks text/plain       = 415
POST /api/attacks json             = 200
GET  /api/alerts?limit=-1          = 400
GET  /api/config (admin)           = 200
DOS_FLOOD alert simulated flag     = True
DOS_FLOOD alert detector           = SignatureDetector
POST /api/login viewer             = 200
GET  /api/config (viewer)          = 403
POST /api/attacks (viewer)         = 403
POST /api/login after 5 failures   = 429, Retry-After: 300
GET  /                             = 200, <title>Network threat detection</title>
GET  /portal/alerts (deep link)    = 200
CSP header                         = present
SSE on subscribe                   = hello frame
```

Browser walk-through of the packaged jar, cache-busted:

- All 9 portal routes render: Overview, Alerts, Incidents, Hosts, Attack lab, Planner, Reports, Control, Admin. Exactly one canvas on `/portal`, `/portal/overview` lands on `/portal`, and `/portal/nope` shows Not found.
- Console: 0 errors and 0 failed requests after a nine page loop in a fresh tab. The only remaining line is a `THREE.Clock` deprecation notice from the 3D library, plus 401 retries from the stream endpoint while signed out.
- 2D topology on Overview: SVG 520 by 545.3, stage 520 by 545.3, panel 603, `fitsStage` and `fitsPanel` both true, stage `scrollHeight` equal to `clientHeight`. Identical numbers at 1.5 times zoom and after a second hard reload with a fresh cache-busting query, so the result is not a warm cache.
- 2D drawing: plate clearly lighter than the background, 19 grid lines at `rgb(167, 184, 172)`, rim visible, every node dot and link inside the card with nothing clipped. Clicking three different hosts updates the selected host card each time.
- 3D scene: plate distinguishable from the background, grid lines visible, rim visible, host models visible as solid shapes. Two screenshots six seconds apart with Rotate on differ; with Rotate off they are identical.
- Controls: the selected map toggle, the toolbar `Start`, every `Enter portal` variant and the landing hero button report background `rgb(217, 169, 58)` with text `rgb(23, 18, 10)`. The selected hero tab underline is `rgb(217, 169, 58)`, and the focused login field reports a `rgb(217, 169, 58)` border. A scan for elements within 25 units per channel of lime returns nothing on the landing page.
- Text colours across the landing page, login and the portal pages resolve only to `rgb(232, 220, 196)`, `rgb(201, 194, 172)`, `rgb(167, 184, 172)`, `rgb(126, 148, 136)`, `rgb(12, 26, 5)`, `rgb(183, 243, 107)` and `rgb(217, 160, 91)`. No white, no neutral grey, no pale blue.
- Timestamps render as `23:35:16` rather than raw ISO strings, and alert rows show badge, attack name, source to target and the simulation pill without overlap.

Test totals: `mvn -q clean test` 127 tests, `npm test -- --run` 12 files and 35 tests, `npx tsc --noEmit` exit 0, `npm run build` clean, jar rebuilt and restarted. One flake was seen in `tests/routing.test.tsx` (the 5 second Router wait) under full parallel load; it passes alone and on the repeat full run.

---

## 7. Deliberate divergences from the written specs

1. Palette. `docs/web-spec.md` specifies a sand and amber scheme. The owner directed a warm cream text ramp on the forest base, gold for emphasis and for every filled control, and lime for live data. What still conforms is the structure: flat surfaces, no shadows, 4 px radii, IBM Plex for the product, Newsreader on the landing page only.
2. `NetworkEvent`. `docs/class-spec.md` describes nine components. The F-04 and F-05 fixes require `simulated` to be domain data rather than a string heuristic, so the record has ten. `NetworkEventTest` pins the new shape and every other constructor path defaults to `false`.
3. F-18 stays as it is. Client role gating in `permissions.ts` only decides which navigation entries are visible; the server enforces every endpoint, which the live matrix re-confirms for a Viewer account. The mapping is locked by `tests/permissions.test.tsx`.
4. Product name. `docs/web-spec.md` still describes the older two word name. The owner directed the full name everywhere, so the spec text and the running product differ on that one string. The spec files were not edited, per `AGENTS.md`.

---

## 8. Open and unverified

- F-02: no git history and no CI workflow. Deliberately excluded by the owner. This is the one item that keeps the project at "demo ready" rather than "production ready".
- Mobile at 390x844 and tablet widths: the browser harness cannot resize its viewport, so the narrow layout was verified from the stylesheet. Breakpoints are 1279, 1100, 960, 900, 860, 720 and 640 px (the sidebar becomes an off-canvas panel behind the menu button, the topbar wraps, and `.panel:has(table)` becomes a horizontal scroll container), and the 640 px block drops the status text, the account name and the wide popovers so nothing overlaps.
- Lighthouse, axe and a full keyboard-only traversal were not run. Focus behaviour was checked by hand for Escape, the dialog roles and the gold ring contrast.
- TLS behaviour (`Secure` cookie path, controlled by `auth.session.secureCookie`) is implemented but untested, because the demo server is plain HTTP.
- Docker build and container run were not executed; the `Dockerfile` was read, not run.
- Long run stability beyond roughly 15 minutes of simulation, memory growth over hours, and the 2,000,000 state cap under load were not exercised.

---

---

## Part B: final gate, phases 2 to 13 (2026-11-08)

### B.1 Environment and commands executed

| Item | Value |
| --- | --- |
| OS | Windows 25H2, PowerShell 5.1 |
| Java | 21.0.13 (Eclipse Adoptium) from `.tools\jdk`, compiled with `release 17` |
| Maven | 3.9.9 from `.tools\maven`, run offline (`-o`) |
| Node | 22.20.0, npm 10.9.3 from `.tools\node` |
| Server under test | `java -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 8099 --seed 7` |

| Command | Result |
| --- | --- |
| `.tools\run-mvn.cmd -o -B test` | BUILD SUCCESS, Tests run: 229, Failures: 0, Errors: 0, Skipped: 0 |
| `.tools\run-npm.cmd test -- --run` | 15 files, 65 tests, all passed, exit 0 |
| `.tools\run-npm.cmd run typecheck` | exit 0, no type errors |
| `.tools\run-npm.cmd run build` | exit 0, assets written to `src/main/resources/web/` |
| `.tools\run-mvn.cmd -o -B package -DskipTests` | BUILD SUCCESS, shaded jar replaces the plain one |
| `java -jar ... --benchmark` | 6 rows printed, exit 0 |
| `java -jar ... --soak 600` | 600 s at 2000 events/s, 0 dropped, exit 0; table in `docs/benchmarks.md` |
| `java "-Dntd.persistence.enabled=true" -jar ... --import-zeek src\main\resources\samples\sample-conn.log` | `1693 flows from 1693 lines, 0 skipped, 40 hosts`, then `stored 1693 flows in data\ntd.db`, exit 0 |
| `powershell -NoProfile -File .tools\smoke.ps1` | every route, gate and refusal answered as documented in B.4 |
| Browser pass over the new panels | Flows Stored, the Admin operations table, a containment block and release, and an evidence export, with 0 console errors and 0 failed requests |

Benchmark, 10000 events per round over 5 timed rounds after a discarded warm-up. The first table in this section was a single 200 event shot that included JIT warm-up, and its gate row was an artifact of a defect rather than a property of the code; both are explained below.

| Benchmark | ops/round | mean us | p50 us | p95 us | p99 us | ops/s |
| --- | --- | --- | --- | --- | --- | --- |
| `flow-recorder.accept` | 10000 | 3.93 | 3.50 | 6.60 | 13.00 | 254,629 |
| `detection.analyze` | 40000 | 0.74 | 0.40 | 2.10 | 4.20 | 1,359,338 |
| `detection.ndr.analyze` | 40000 | 0.08 | 0.10 | 0.10 | 0.20 | 11,841,537 |
| `ml.features` | 10000 | 0.33 | 0.30 | 0.50 | 1.40 | 3,026,653 |
| `ml.kmeans.train(2000)` | 1 | 11,987.58 | 10,084.10 | 20,955.00 | 20,955.00 | 83 |
| `alerts.quality-gate` | 10000 | 2.96 | 2.30 | 4.60 | 8.50 | 337,734 |

The old table reported `alerts.quality-gate` at 275.96 us against 5.85 us for four detectors, and an earlier run at 105.71 us, and called it an outlier that sat above any achievable alert rate. It was a defect. `AlertQualityGate.prune()` walked the entire fold map on every delivery, so the row measured the map size, not the gate: the 200 event shot scanned 200 keys and the 10000 event shot scanned 10000. The prune is now bounded to 16 entries per delivery, the row is 2.96 us, and the fold window is still enforced. `docs/benchmarks.md` records that fix together with two more the soak exposed, a full active-flow scan on eviction in `FlowRecorder` and a synchronous file write per alert in `EventLog`.

### B.2 Findings

| ID | Severity | Area | Status | Title |
| --- | --- | --- | --- | --- |
| F-24 | High | Durable store | Fixed | `flush()` could report success before the batch reached the disk |
| F-25 | Low | Notifications | Fixed | The error description was published after the dropped counter |
| F-26 | Medium | Zeek import | Fixed | `zeek.enabled` shipped and documented but read nowhere |
| F-27 | Low | Docs / CLI | Fixed | The documented import command could not work, and PowerShell splits an unquoted `-D` argument |
| F-28 | Low | Tests | Fixed | `AlertQualityGate` and the engine gate seam had no coverage at all |
| F-29 | Low | Tooling | Fixed | `smoke.ps1` crashed on the single page shell |
| F-30 | Low | Tests | Fixed | Three new tests asserted the wrong thing |

#### F-24, the one that mattered

`WriteBehindQueue` drained `pending` inside `synchronized (pending)`, released the lock, and only then marked the batch in flight inside `write()`. A `flush()` that landed in that window saw an empty queue and nothing being written, returned `true`, and its caller read the store before the commit had happened. `PersistenceTest.recorderCloseListenerReachesStore` read zero rows at the assertion that followed the flush, while `closeAllOpen()` had correctly reported the key it closed.

The batch is now marked in flight inside the same lock that drains it, so "taken off the queue" and "reached the disk" cannot be confused. `flush()` is documented as a durability barrier rather than a queue length check, because that is the contract the persistence service and its callers depend on.

#### The rest

- F-25: `dropped.addAndGet(...)` ran before `lastError.set(...)`, so a reader watching the counter could see `1` with a null description. The description is published first.
- F-26: the offline importer ran regardless of `zeek.enabled`. `Main.importZeek` now reads the key and prints a note when it is off.
- F-27: two separate defects in the walkthrough. The README import command omitted the store override, so following it printed `The durable store is disabled`. Separately, Windows PowerShell 5.1 splits an unquoted `-Dntd.persistence.enabled=true` into a main class of `.persistence.enabled=true`, so the line is now quoted and the reason is stated next to it.
- F-29: `Invoke-WebRequest` without `-UseBasicParsing` throws a `NullReferenceException` from the IE engine on the streamed shell. The script uses basic parsing and now also probes the nine new endpoints and the three Admin only reads.
- F-30: `AuditLogTest` expected a denied or failed count of one for a null outcome, but a null outcome normalises to `ALLOWED`. `OperationsApiTest` asserted the admin actor on every `auth.login` row while the same test also opens a viewer session. `MlTest` expected exactly one alert from an outlier, but the model learns from the stream it scores, so a few warm up flows legitimately score at or above the threshold. All three were assertion errors; the production behaviour was correct in each case.

### B.3 Capability matrix

| Capability | Key | Default | Where it shows |
| --- | --- | --- | --- |
| Flow telemetry | `flow.enabled` | on | `GET /api/flows`, the Flows page |
| Durable store | `persistence.enabled` | off | `GET /api/flows/history`, `/api/persistence/status`, `/api/compliance/summary` |
| Audit trail | `audit.enabled` | on | `GET /api/audit`, the Admin audit panel |
| Zeek import | `zeek.enabled` | on | `--import-zeek <file>` |
| Threat intel | `intel.enabled` | off | the signature detector via `intel.feed` |
| Alert quality gate | `alerts.dedupe.enabled`, `alerts.minSeverity` | off | `GET /api/alert-quality` |
| Beaconing detector | `detection.beaconing.enabled` | off | `DetectorFactory.createNdr()` |
| Exfiltration detector | `detection.exfil.enabled` | off | `DetectorFactory.createNdr()` |
| Lateral movement detector | `detection.lateral.enabled` | off | `DetectorFactory.createNdr()` |
| Flow anomaly model | `ml.enabled` | off | `GET /api/ml/status`, the Admin operations table |
| Correlation | `correlation.enabled` | off | `GET /api/correlation/status` |
| Containment | `containment.enabled`, `containment.enforce` | off | `GET /api/containment`, the Admin containment form |
| Notifications | `notifications.enabled` | off | `GET /api/notifications` |
| Evidence bundles | `forensics.enabled` | off | `POST /api/forensics/export` |
| Benchmarks | none | command line | `--benchmark [events]` |

### B.4 Live matrix

Against the packaged jar on port 8099 with the shipped defaults:

```
POST /api/login admin                       = 200, csrf cookie issued
POST /api/sim/start with token              = 200
GET  /api/flows?limit=4                     = 200, 4 rows
GET  /api/flows?limit=1                     = 200, 1 row
GET  /api/flows?port=abc                    = 400
GET  /api/alert-quality                     = 200, dedupe off, 0 tracked
GET  /api/ml/status                         = 200, enabled false, model disabled
GET  /api/correlation/status                = 200, enabled false
GET  /api/containment                       = 200, enabled false, 0 blocked
GET  /api/notifications                     = 200, enabled false
GET  /api/compliance/summary                = 200, storeEnabled false
GET  /api/audit                             = 200, entries newest first
GET  /api/persistence/status                = 200, enabled false
GET  /api/flows/history?limit=5             = 503, the store is off
viewer GET /api/audit                       = 403
viewer GET /api/compliance/summary          = 403
viewer GET /api/persistence/status          = 403
GET  /portal/flows                          = 200, root div present
```

Offline paths against the same jar:

```
--benchmark 200                                   = 5 rows, exit 0
--import-zeek sample-conn.log                     = refused, store off, exit 0
-Dntd.persistence.enabled=true --import-zeek ...  = 1693 flows stored, exit 0
```

Browser pass, with the store, the model, correlation, containment, notifications, forensics and the quality gate switched on for the run:

- Flows Live said there was nothing to show yet, which was true because the simulator had not been started on that instance. Stored said `Read from the durable store` and rendered 500 rows from the imported capture, which is the `flow.api.max` cap.
- Admin operations reported Flow model `Cold` at `0 samples`, Correlation `On` at `2 signal minimum, 600s window`, Containment `On` at `0 blocked, enforcement off`, Notifications `On` at `0 recorded`.
- Blocking `203.0.113.77` for 45 minutes answered `Contained 203.0.113.77 for 45 minutes.`, added the row with reason `browser check` and actor `admin`, and Release answered `Released 203.0.113.77.`
- Export answered `Evidence bundle written to evidence\bundle-20261108T072405Z.` and the directory holds `flows.json`, `alerts.json`, `audit.json`, `incidents.json` and `manifest.json`. The generated `evidence/` directory is now ignored by version control, which it was not.
- No console errors and no failed requests across the pages visited.

### B.5 Regression tests

Backend, 229 tests in 41 classes. The classes added for phases 1 to 13:

| Class | Tests | Capability |
| --- | --- | --- |
| `flows.FlowRecorderTest` | 13 | flow telemetry |
| `persistence.PersistenceTest` | 6 | durable store |
| `security.AuditLogTest` | 5 | audit trail |
| `zeek.ZeekConnLogParserTest` | 5 | offline import |
| `intel.ThreatIntelTest` | 6 | threat feed |
| `detection.NdrDetectorsTest` | 6 | beaconing, exfiltration, lateral movement |
| `detection.EventObserverTest` | 1 | the event tap the recorder and the model hang from |
| `detection.AlertQualityGateTest` | 10 | dedupe, severity floor, bounds, the cooldown seam |
| `ml.MlTest` | 6 | feature extraction, training, scoring, alerts |
| `correlation.SiemCorrelatorTest` | 4 | multi signal escalation |
| `containment.ContainmentServiceTest` | 7 | blocks, expiry, the audit of who asked |
| `notify.NotificationServiceTest` | 7 | outbox, floor, webhook, bounds |
| `forensics.EvidenceExporterTest` | 6 | bundle layout, manifest digests, truncation |
| `compliance.ComplianceServiceTest` | 3 | the single summary read |
| `bench.BenchmarksTest` | 5 | the five measurements, zero safe, the report |
| `web.OperationsApiTest` | 9 | the new endpoints, their role gates and their refusals |

Two of those classes exist because the gate found the gap: `AlertQualityGateTest` covers a class that had no test and a seam in `DetectionEngine` that had none either, and `EventObserverTest` covers the tap the whole telemetry path hangs from.

Client, 65 tests in 15 files. `tests/operations.test.tsx` is new, 11 cases over the Admin operations table, the containment form and its 409, a release that is not blocked, a refused export, the compliance table, the audit rows, the disabled export button and the viewer gate. `tests/flowsPage.test.tsx` gained three stored mode cases on top of its four: a stored read that replaces the live rows, an empty store that says so, and a 503 that names `persistence.enabled` and offers a retry.

### B.6 Deliberate divergences

1. Defaults. Ten capability switches ship. Three are on (`flow.enabled`, `zeek.enabled`, `audit.enabled`) and seven are off. The three that are on change nothing an operator can see until they open a new page or run the new command; the seven that are off answer with their own disabled state rather than pretending to work, which is what the live matrix in B.4 shows.
2. No sixth pattern. The alert gate, the admission predicate and the event observer are seams on existing classes (Strategy and Observer), not new patterns. `docs/class-spec.md` states this explicitly.
3. `DetectorFactory.createAll()` still returns exactly four detectors. The NDR family is `createNdr()`, so the phase 0 contract test is untouched, and `EnumsTest` still pins exactly four attack types.
4. The class spec counts 105 elements, up from 69. `docs/class-spec.md` was rewritten around that number.

### B.7 Open and unverified

- F-02 is unchanged: no version control and no CI. It remains the one item that separates "demo ready" from "production ready".
- The new client panels were clicked through in a browser with every capability on (B.4). The containment form, the release, the export and the operations table were exercised for real; the Flows Live switch was not, because that instance had no simulator running.
- The Docker build was not executed. The `Dockerfile` was read, not run.
- The benchmark figures are one 200 event shot and include warm up.
- TLS behaviour, mobile widths, long run stability and the 2,000,000 state cap remain as listed in Part A.

What the gate says about the work: thirteen phases landed without disturbing a single earlier contract, and the suite caught three defects in the new code (a flush race, an error publishing order, and a switch that was documented but never read). What it does not say is that the system has been exercised by a human in a browser for the new pages, or that it has ever run under version control.

---

## Part C: completion pass gate (2026-11-08)

Part B left 22 items of the 74 numbered requirements at `PARTIAL` and 52 at `MISSING`. This part is the pass that closed them and re-measured the whole system, so the numbers here supersede the counts quoted in Part A and Part B wherever the two disagree.

### C.1 Commands executed against the final tree

| Command | Result |
| --- | --- |
| `mvn -o -B test` | BUILD SUCCESS, Tests run: 259, Failures: 0, Errors: 0, Skipped: 0, across 46 classes |
| `mvn -o -q -B package -DskipTests` | BUILD SUCCESS, `threat-detection-1.0-SNAPSHOT.jar` at 23.9 MB |
| `npm test -- --run` | 15 files, 66 tests, all passed |
| `npm run typecheck` | exit 0, no type errors |
| `npm run build` | exit 0, output written to `src/main/resources/web/` |
| `java -jar target\threat-detection-1.0-SNAPSHOT.jar --web --port 8097 --config <profile>` | 31 keys layered, `Restored schema 2`, `/healthz` answered 200; the profile used for this pass was removed in the cleanup phase, and any properties file named with `--config` supplies the same 31 keys |

The backend is 141 compiled sources in 23 packages, up from 105 in Part B. The client is unchanged in shape at 15 pages and 15 test files.

### C.2 The audit is closed

`docs/completion-audit.md` now records 72 of the 74 items as `EXISTS`, with the file, symbol or test that decides each one, and the other two as `REMOVED` because the owner withdrew the scripted demo path after this pass. The original Step 0 measurement (2 `EXISTS`, 20 `PARTIAL`, 52 `MISSING`) is preserved in that document, so the distance travelled stays readable instead of being overwritten.

### C.3 Test classes that grew or appeared after Part B

| Class | Tests | Capability |
| --- | --- | --- |
| `persistence.PersistenceTest` | 8 (was 6) | a v1 file migrated in place, a corrupt file that degrades to memory |
| `service.RestoreTest` | 1 | alerts, incidents, blocks, audit rows and the model summary read back through a second facade on the same file |
| `imports.ImportServiceSampleTest` | 1 | the bundled capture replayed: 1693 flows, 134 alerts, every label accounted for and four traps silent |
| `simulation.ScenarioServiceTest` | 7 | the seven presets, including the beaconing jitter and the lateral sweep |
| `intel.ThreatIntelTest` | 12 (was 6) | domain and digest matching, expiry, a reload that keeps the old feed |
| `detection.NdrDetectorsTest` | 8 (was 6) | the allowlists that keep a known backup out of the exfiltration rule |
| `bench.SoakTest` | 5 | the sustained load, queue depth and latency split |

The sample replay test is the one worth reading: it pins the exact per label alert counts of the shipped capture, so a threshold change that starts alerting on the 30 NTP polls or the 94 MB internal backup fails the suite with the label named.

### C.4 Browser pass on the packaged jar

A properties profile with the store, intel, forensics and every detector on was layered on the packaged jar on port 8097. Signed in as `admin`.

- Overview: simulation started, the stage moved from `Stage 1 of 4, Recon` to `Stage 2 of 4, Access`, the feed read `6 detected, 1 reached the feed, 17% delivery ratio, 5 folded repeats, 0 suppressed`, and the counters moved to `18 Active nodes, 1 Compromised nodes`.
- Flows: live mode read `18 Records, 18 Still open`. Stored mode answered `Read from the durable store` and `No stored flows yet. They appear once the store is on and flows close.`
- Alerts and Incidents: seven alert rows with Time, Severity, Type, Source, Target, Count and Status, and one open incident for `10.0.0.1` holding seven alerts.
- AttackLab: the `Indicator contact` preset answered `Indicator contact: 3 events submitted from 10.0.0.1 to 10.0.0.3.`
- Admin, Operations status, quoted row by row: Flow model `Cold` at `1 samples, 0 clusters, threshold 0.9, 0 scored, 0 anomalies, 0 alerts, 0 excluded from training`; Correlation `On` at `5 correlated from 7 signals, 2 signal minimum, 600s window`; Kill chains `On` at `1 rules, 1 matched, last Recon to exfiltration`; Containment `IPS` at `0 blocked, 0 events dropped, 0 refused by a safeguard`; Pipeline metrics `Live` at `79 events processed, 0 queued, 0 dropped, 119 detected, 7 delivered, 125 rows written, 17 MB heap, up 3 min`; Notifications `On` at `12 recorded, 0 sent, 0 failed, 0 dropped`.
- Admin, evaluation and intel: the panel read `0 labelled flows (0 attack, 0 benign) from 0 replay runs` with its explanation, which is correct on an instance that has imported nothing. The intel panel read feed `threat-intel.json`, detector `on`, `49` indicators (19 addresses, 15 domains, 15 digests), `0` skipped, `1` expired.
- Admin, compliance: store at `target\browser-pass\ntd-demo.db`, `1 flows, 12 alerts`, `1440 minutes, cutoff 2026-11-07T11:56:27.920585400Z`, `5 of 2000 entries, 0 denied, 0 failed`. The audit trail listed `config.read`, `scenario.run` and `auth.login` by `admin`, all `Allowed`.
- Admin, containment and evidence: blocking `198.51.100.77` for 45 minutes answered `Contained 198.51.100.77 for 45 minutes.`, Release answered `Released 198.51.100.77.`, and Export answered `Evidence bundle written to target\browser-pass\evidence\bundle-20261108T115704Z.` with `Last bundle: 5 files, 8520 bytes, manifest fb9dd9ed85e037d0.`
- Control: mode `IPS`, `0 contained, 0 events dropped, 0 automatic. The guards refused 0: 0 allowlisted, 0 rate limited, 0 would split the network.`
- Console and network: one `THREE.Clock` deprecation warning on the map page and no errors; every request answered 200.

One honest discrepancy. The Stored tab answered "no stored flows yet" at the moment it was opened while the compliance panel later counted one stored flow. Both are correct: a flow is written when it closes, and the rows on screen were still open. It is worth knowing before someone reads the two panels as contradictory.

### C.5 What the completion pass found and fixed

1. The store leaked two JDBC handles when a connection opened and then failed to configure. On Windows the file stayed locked, so a corrupt database could not even be deleted afterwards. `Database` now opens into locals, closes both handles on `SQLException` or `RuntimeException`, and rethrows; `PersistenceTest.corruptDatabaseDegradesToMemory` holds the line and the process no longer keeps a handle on the bad file.
2. The Admin client's shared mock world predated two endpoints added for the evaluation and metrics panels. `Promise.all` rejected on the missing mocks, so nine cases in `tests/operations.test.tsx` observed a page stuck on `Loading operations status.` and the export they clicked was still disabled. The mock now mirrors the current API types, and the table assertions cover the metrics row, the kill chain row, the labelled flow count and the intel count, which had no coverage before.
3. The containment badge rendered `Ips` for mode IPS, because every status string went through the word labeller. The two modes are now kept upper case, and the operations test asserts `IPS`.

### C.7 Open and unverified

- F-02 is unchanged and remains the one item that separates demo ready from production ready: no version control and no CI. The owner is handling the repository separately.
- The Docker image was read, not built.
- The benchmark figures in `docs/benchmarks.md` come from one host, one synthetic shape and five rounds.
- TLS termination, mobile widths, a multi day run and the 2,000,000 state cap remain as listed in Part A.
- The sample capture replay is deterministic for a fixed configuration and seed. A deliberate threshold change will change alert counts, and the test is meant to fail until they are re-baselined on purpose.
