# Security posture

This document describes how the server authenticates people, what it refuses to
do, and which protections are on by default. It is written for whoever operates
the build, so every claim below names the configuration key or the route that
implements it.

The threat model is a single server operated by a small team on a trusted
network, reached through a reverse proxy that terminates TLS. The build does not
try to defend against a compromised host, a hostile administrator or an attacker
who can rewrite the SQLite file. Those are out of scope and are called out again
in "Known limitations".

## Deployment modes

There are exactly two modes, and the build says which one it is in.

| Mode | `app.demoMode` | Behaviour |
| --- | --- | --- |
| Demo | `true` (packaged default) | The three seeded accounts work, a banner is printed at startup, `GET /api/demo` names the accounts and the web client shows a strip on the sign-in page and in the shell |
| Production | `false` | Startup refuses to continue unless every account has a credential that is not the shipped one |

In production mode `Main` calls `SecurityPolicy.startupProblems` before the facade
is built. Every problem is printed, and the process exits with status 2 rather
than starting half configured. A problem is any of: a missing username, a
missing credential, the shipped demo hash, or a plaintext password that fails the
policy below. The checks live in `security/SecurityPolicy`.

Warnings that do not stop the process are printed afterwards. With the defaults
they are "the session cookie is not Secure" and, in demo mode, "demo mode is on".

## Accounts and roles

Accounts come from `config.properties`, and each one can be overridden from the
environment, which takes precedence over the file.

| Role | Username key | Credential key | Environment override |
| --- | --- | --- | --- |
| Admin | `auth.defaultUsername` | `auth.defaultPassword` | `NTD_ADMIN_PASSWORD` |
| Analyst | `auth.analystUsername` | `auth.analystPassword` | `NTD_ANALYST_PASSWORD` |
| Viewer | `auth.viewerUsername` | `auth.viewerPassword` | `NTD_VIEWER_PASSWORD` |

The permissions are decided per request in `web/ApiRoutes`, never on the client.

| Capability | Viewer | Analyst | Admin |
| --- | --- | --- | --- |
| Read state, network, alerts, events, flows, incidents, reports, quality, model and correlation status | yes | yes | yes |
| Launch a simulated attack (`POST /api/attacks`) | no | yes | yes |
| Start, stop and reset the simulation, import Zeek, run the response planner | no | yes | yes |
| Containment block, mode and release | no | no | yes |
| Notification test and runtime control | no | no | yes |
| Table export (`GET /api/export/{kind}`) and incident bundle | yes | yes | yes |
| Evidence bundle written to disk (`POST /api/forensics/export`) | no | no | yes |
| Runtime retention change | no | no | yes |
| Read the configuration, the audit trail, the store status and the compliance summary | no | no | yes |

A refusal is answered with `403` and an empty body, and it is audited with the
role that asked, so probing an Admin route leaves a trail.

## Password policy

A password is checked when its plaintext is readable, which is the case for an
environment override or a plaintext value in the file. A stored hash cannot be
checked for strength, because the plaintext is not there to measure, so a hash
that differs from the shipped one is accepted on the assumption that whoever
replaced it applied the policy.

The rule is in `SecurityPolicy.passwordProblem`:

* not blank;
* at least `auth.password.minLength` characters, with 8 as a hard floor;
* not the username, ignoring case;
* not one of the shipped demo passwords;
* with `auth.password.requireClasses=true`, at least one letter and one digit.

Passwords are stored as `pbkdf2$iterations$salt$hash` using PBKDF2WithHmacSHA256
with 210000 iterations. Verification is constant time for both the hash and the
plaintext fallback, so a wrong password does not leak how wrong it is through
timing.

## Sessions and re-authentication

| Control | Key | Default |
| --- | --- | --- |
| Idle timeout | `auth.session.timeoutSeconds` | `28800` |
| Hard lifetime from sign-in | `auth.session.absoluteTimeoutSeconds` | `43200` |
| Cookie lifetime | `auth.session.maxAgeSeconds` | `0` (browser session) |
| New session id on sign in | `auth.session.rotateOnLogin` | `true` |
| Secure cookie attribute | `auth.session.secureCookie` | `false` |

The session cookie is `HttpOnly`, `SameSite=Lax` and, when `secureCookie` is on,
`Secure`. Sign in invalidates the session the browser arrived with and writes the
attributes into a fresh one, which defeats session fixation. Sign out invalidates
the session server side. The absolute timeout is enforced on every API call: a
session older than the limit is invalidated, answered with `401` and audited as
`auth.expired`, so keeping a session warm does not extend it.

A CSRF token is issued at sign in as a `csrf` cookie (`SameSite=Strict`) and must
be echoed in `X-CSRF-Token` on every mutating call. The check is in the API
before-filter and applies to `POST`, `PUT`, `PATCH` and `DELETE`.

Three actions ask for the password again even though the caller is already signed
in, because each one changes the security posture of a running system:

* `POST /api/containment/mode`
* `POST /api/notifications/control`
* `POST /api/retention`

`auth.reauth.enabled` turns the gate on, `auth.reauth.freshSeconds` remembers a
successful entry for that many seconds (`0` asks every time), and
`auth.reauth.maxAttempts` / `auth.reauth.windowSeconds` throttle repeated
failures. A wrong password answers `401`, a throttled attempt answers `429` with
`Retry-After`, and both are audited with the reason. The check uses
`AuthService.verify`, which does not touch the facade's current user, so a failed
re-entry cannot change who the server thinks is signed in.

## Login throttling

Failed sign-ins are counted twice: once against the account name and once against
the client address. The account key stops a password guess against one name, the
address key stops one client from spreading the same guesses across every name,
and each key expires on its own window, so a lockout lifts by itself.

The defaults are five failures in five minutes (`auth.login.maxAttempts`,
`auth.login.windowSeconds`). A blocked attempt answers `429` with a
`Retry-After` header and never says whether the account exists. A wrong password
and an unknown username both answer `401` with an empty body, and the audit entry
records `bad credentials` for both.

The counters live in memory, so a restart clears them. That is a deliberate
trade-off for a single node: a durable counter would have to be shared and
pruned, and the window is short enough that a restart is a cheaper defence than
the operational cost.

## Transport and response headers

The application speaks plain HTTP and expects TLS to be terminated in front of
it. `deploy/Caddyfile` is a working example that issues a certificate from Caddy's
local CA for `localhost` and forwards to the app over the compose network;
`docker-compose.yml` wires the two together on port 8443. The same file sets HSTS
at the proxy, which is the correct place for it, because the app never sees the
TLS connection.

Every response carries these headers from `WebServer.start`:

| Header | Value | Why |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'self'` with `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`, `form-action 'self'` | The single page app loads only its own bundle and fonts |
| `X-Content-Type-Options` | `nosniff` | Stops a browser from reinterpreting a response |
| `X-Frame-Options` | `DENY` | Clickjacking, for browsers that ignore `frame-ancestors` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Keeps query strings out of outbound referrers |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | The app needs none of them |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context |
| `Cross-Origin-Resource-Policy` | `same-origin` | Stops other origins embedding the responses |
| `Strict-Transport-Security` | `max-age=<n>; includeSubDomains` | Only when `auth.hsts.enabled=true`, so a plain HTTP deployment is not poisoned |

`script-src` and `style-src` allow `'unsafe-inline'` because the client ships
inline bootstrap code and inline style attributes. Removing that would need a
nonce pipeline in the build; the CSP note in "Known limitations" records it.

Requests are also checked before any handler runs:

* a body larger than `http.maxBodyBytes` (8 MiB by default) answers `413`;
* a mutating request whose `Origin` is present and does not match `Host` answers
  `403`, which is a second CSRF boundary behind the token check;
* an unknown `/api` path answers `404` rather than falling through to the single
  page app.

Unexpected exceptions are caught once. The stack trace goes to the event log and
the client gets `{"error":"internal server error"}` with status `500`, so a
failure does not return framework details or a Java class name.

`GET /healthz` is unauthenticated by design and returns `{"status":"ok"}`. It
exposes nothing but liveness, which is what a container health check needs.

## Audit trail

`security/AuditLog` records who asked for what. Each entry carries a sequence
number, a timestamp, the actor, the action, the target, the outcome
(`ALLOWED`, `DENIED`, `FAILED`) and a detail line.

Recorded actions include `auth.login`, `auth.logout`, `auth.expired`,
`config.read`, `audit.read`, `store.status`, `import.zeek`, `export.<table>`,
`incident.bundle`, `evidence.export`, `retention.update`, `containment.block`,
`containment.mode`, `containment.release`, `notification.test`,
`notification.control` and `compliance.read`. Every one of them records a
refusal as well as a success.

Text that came from the network is flattened before it is stored: control
characters and newlines become spaces, and each field has a cap (64 characters
for the actor and action, 200 for the target, 400 for the detail). An actor name
cannot stretch an entry over several lines or inject a terminal escape into a log
viewer. With `persistence.enabled=true` the ring is written through to the
`audit_entries` table as an `INSERT` and restored on startup, so the trail
survives a restart.

There is no update or delete path for an audit row. The only statement that
removes one is the retention sweep, which is itself a runtime action restricted to
Admin, requires a password re-entry, and writes `retention.update` before the rows
disappear. That is the append-only rule this build can honestly claim.

`GET /api/audit` is Admin only and returns the newest entries plus the denied and
failed counters.

## Secrets

Credentials belong in the environment, not in the image. The Dockerfile does not
copy a secret and does not start in production mode; `docker-compose.yml` shows
the commented production block that reads `NTD_ADMIN_PASSWORD` and friends from a
`.env` file. `JAVA_TOOL_OPTIONS` is the supported way to set `-Dntd.*` options in
a container.

There is no key store, no rotation API and no secret in the SQLite file. A
credential is read once at startup, so changing an environment variable requires a
restart. That is stated here rather than implied.

## Container hardening

The runtime stage of the `Dockerfile`:

* installs `curl` only for the health check, and removes the package lists;
* creates a system user `ntd` with uid 10001 and no login shell;
* creates `/app/data` and `/app/evidence` and hands them to that user;
* switches to `USER ntd` before the entry point;
* enables persistence and points it at `/app/data` through `JAVA_TOOL_OPTIONS`;
* declares `HEALTHCHECK` against `/healthz`;
* runs `java -jar` as PID 1 through `exec`.

`docker-compose.yml` runs both containers with `no-new-privileges:true`, keeps the
store and the evidence directory on named volumes, and starts the proxy only
after the app reports healthy.

## Dependency review

Both dependency trees were listed before this document was written.

`mvn dependency:tree` (written to `target/dependency-tree.txt`) resolves:

| Artifact | Version |
| --- | --- |
| `io.javalin:javalin` | 6.3.0 |
| `org.eclipse.jetty:jetty-server` (with http, io, servlet, webapp, websocket) | 11.0.23 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.17.2 |
| `org.slf4j:slf4j-api` | 2.0.16 |
| `org.slf4j:slf4j-simple` | 2.0.13 |
| `org.xerial:sqlite-jdbc` | 3.46.1.3 |
| `org.jetbrains.kotlin:kotlin-stdlib` | 1.9.25 |
| `org.junit.jupiter:junit-jupiter` | 5.10.2 (test) |

`npm audit` over the 220 packages in `web-client` reports zero vulnerabilities. To
repeat both checks:

```
.\.tools\run-mvn.cmd -o dependency:tree "-DoutputFile=target/dependency-tree.txt"
cd web-client
..\.tools\run-npm.cmd audit
```

The syntax tree has no transitive dependency outside the list above, and the
client has no runtime dependency other than React and Vite's build output. Note
that `slf4j-simple` is pinned to 2.0.13 while `slf4j-api` resolves to 2.0.16; the
binding is binary compatible and the mismatch is recorded here rather than hidden.

## Configuration reference

| Key | Default | Meaning |
| --- | --- | --- |
| `app.demoMode` | `true` | Accept the shipped accounts and print the demo banner |
| `auth.password.minLength` | `12` | Minimum plaintext length, floor of 8 |
| `auth.password.requireClasses` | `true` | Require a letter and a digit |
| `auth.reauth.enabled` | `true` | Ask for the password before a sensitive change |
| `auth.reauth.freshSeconds` | `0` | Remember a successful entry for this long |
| `auth.reauth.maxAttempts` | `5` | Failed re-entries before throttling |
| `auth.reauth.windowSeconds` | `300` | Throttle window |
| `auth.login.maxAttempts` | `5` | Failed sign-ins per account and per address |
| `auth.login.windowSeconds` | `300` | Sign-in throttle window |
| `auth.session.timeoutSeconds` | `28800` | Idle timeout |
| `auth.session.absoluteTimeoutSeconds` | `43200` | Hard lifetime from sign-in, `0` disables |
| `auth.session.secureCookie` | `false` | Add `Secure` to the session cookie |
| `auth.csrf.enabled` | `true` | Require the double submit token |
| `auth.hsts.enabled` | `false` | Send HSTS, only correct behind TLS |
| `auth.hsts.maxAgeSeconds` | `31536000` | HSTS lifetime |
| `http.maxBodyBytes` | `8388608` | Largest accepted request body |
| `audit.enabled` / `audit.maxRecords` | `true` / `2000` | Trail on, ring size |

## Known limitations

* No multi-factor authentication, no external identity provider and no per-user
  credential store. The three accounts are fixed roles.
* The CSRF token and the login, re-entry and session state live in server memory.
  A restart signs everyone out and clears throttles.
* Login throttling is per process, so two instances behind a load balancer keep
  two independent counters.
* The CSP allows inline script and style because the client build does not emit
  nonces. Moving to a nonce or hash based policy is the next hardening step.
* Audit retention is bounded by `audit.maxRecords` in memory and by the store
  retention policy on disk. There is no external write-once sink.
* TLS is the proxy's job. Enabling `auth.hsts.enabled` without TLS in front will
  make browsers refuse plain HTTP for the max-age period.
* The application does not defend against an operator with filesystem access, who
  can read the store and rewrite the audit table.
