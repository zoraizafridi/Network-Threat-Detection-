# Web spec (replaces docs/ui-spec.md)

The Swing GUI is removed. The product is a website: a landing page, then a portal.
The Java backend stays the single source of logic. The React client only displays
and sends commands, through the web package, which calls IncidentResponseFacade.

## Stack
Client (folder web-client/): Vite, React, TypeScript, React Router, Zustand (state),
three + @react-three/fiber + @react-three/drei (3D map), GSAP + ScrollTrigger, Lenis,
React Bits components (copied into the repo as source; check its docs for the install command).
Server (package pk.ooad.ntd.web): Javalin, JSON with Jackson. Depends only on service and domain.
Tests: Vitest + Testing Library for the client, JUnit for the API.
Check current versions before pinning. No component library left in a default look.

## Identity
Quiet field-station console. Forest green and sand. Dense, factual, flat.

## Colour tokens (only these)
sand #E8DCC4 | surface #F3ECDD | line #C9BA9A | ink #1F3D2B | ink-muted #4A5E4F
forest #1F3D2B | forest-raised #2A4F39 | forest-line #3E6650 | sand-on-forest #E8DCC4 | muted-on-forest #B9C4B3
Status on sand: normal #2F6B45, suspicious #7A4F08, compromised #A8321F, low #3F6182
Status on forest and in 3D: normal #8FBF9F, suspicious #E0A63B, compromised #E5604D, low #8DB1D6
No separate accent colour. Primary button: forest fill, sand text. Status colours mean status only,
always with a text label. Text contrast at least 4.5:1, body 7:1.

## Type and spacing
Text IBM Plex Sans (400, 600). Data IBM Plex Mono. Self-hosted. Scale 12, 13, 14, 16, 20, 28, 48, 72.
Landing headlines only may use Newsreader roman, self-hosted. Portal pages stay on IBM Plex.
Spacing multiples of 4 (4, 8, 12, 16, 24, 32, 48, 64, 96). Radius 0 or 4. 1px borders. No shadows.
Sentence case. No em dash character anywhere in UI text, comments or docs.

## Still banned
Any gradient text, grain or noise, glassmorphism, emoji, Inter, Space Grotesk,
Instrument Serif, serif italic accents, Lucide or any icon set used everywhere, coloured left-border cards,
three icon boxes in a row, shadcn or Tailwind default looks,
sections that fade in on scroll, a beam or glow following the cursor, hover effects that fade
(hover is an instant swap), inconsistent spacing, buzzword copy.
Icons: drawn in code, 1.5px stroke, only for the four asset types. Everything else is text.

## Motion rules (what Lenis and GSAP are for)
Allowed: scroll-linked motion (pinned sections, scrubbed timelines, translate and scale driven by scroll
position), route transitions (a solid panel wipes across, no fade), camera moves, state-change animation.
Not allowed: fade-in on scroll, stagger-fade lists, hover fades, cursor-following effects, looping decoration.
Landing exception: the hero may play one load timeline on the headline block, about 800ms, and one connection-drawing timeline on the network, about 1200ms. The landing hero holds a 3D drawing of the sample hosts and their real links, in sand and muted green, with one illustrated compromised host. A scrubbed timeline moves one signal along a real route, brings the camera closer, and draws the outer links, then continues through Detect, Score, Plan and Report. It is an illustration. Reduced motion shows the final state with a still camera. Landing headlines are sentence case in Newsreader. Mono kickers may be uppercase. The four moves are a ruled diagram, not cards. Enter portal moves that same network to fill the view, then a forest panel wipes for 600ms into role selection, or into the portal when a session already exists. The public landing does not mount the live network map, because that map needs a session. The public demonstration does not call the server.
Easing: power3.out or expo.out only. No bounce, no elastic.
Durations: route wipe 600ms, camera move 900ms, node colour change 300ms, compromise ring 600ms once,
link to red 300ms, backbone draw-on 600ms, new alert row tint 800ms, number count 350ms.
Respect prefers-reduced-motion: Lenis off, timelines jump to their end state, 3D camera moves are instant.
One Lenis instance, driven from the GSAP ticker:
  lenis.on('scroll', ScrollTrigger.update);
  gsap.ticker.add((t) => lenis.raf(t * 1000));
  gsap.ticker.lagSmoothing(0);
Kill ScrollTriggers and tweens on unmount. Animate transform and opacity only, never layout properties.
Lenis runs on the landing page only. Inside the portal use native scroll in panels, so tables stay usable.
Add: “Motion off under prefers-reduced-motion.”

## React Bits rules
Use a component only if it passes the banned list. Check each one before adding it.
Likely fine: count-up numbers, decrypt or scramble text for IP addresses and hashes, a menu or dock built flat.
Decrypt text is copied in the repo for data strings. It is not mounted on the landing.
Likely not fine (violate the list): gradient text, aurora or beam or particle backgrounds, spotlight or glass cards,
splash or trail cursors, blur text. Restyle to the tokens, or do not use it. Say which ones were used.

## Pages
Landing (public, Lenis + GSAP):
 1. Asymmetric hero on flat forest. A ruled bar: Field station, Detect, Score, Plan, Report, and a text button, "Enter portal". Left column: mono label, a large left-aligned Newsreader headline with fixed line breaks, one factual line, Enter portal, and Explore the system. Centre: the sample network in 3D, about half the hero, sand links on forest, one illustrated compromised host, one signal. A short caption states that the loaded sample starts Normal. Right: hosts 18, links 21, detectors 4. One scrubbed timeline carries the signal and draws Detect, Score, Plan and Report. Lenis drives the scroll. Reduced motion shows the final drawing and a still network.
 2. A ruled process, not cards. Detect, Score, Plan, Report in four columns on desktop and stacked rows on a narrow screen. Each has a number, the same sentence as before, and one 1.5px diagram: detector gates, a 0 to 100 score, a backbone path, a report with status labels.
  3. Inside the network, on sand. A forest console shows the sample router backbone, four servers and two workstations, with real names and addresses, plus the host fields for Database Server 1 at rest: Normal, risk 0 of 100, no alerts. The section says it is a sample preview, not a live session.
  4. A public demonstration titled "One event. Then the response." The visitor picks a source host and a target host from the sample, then a local timeline shows the marker, the four detectors, an example risk reading, one hop chain of published sample links, and report lines. It does not call the server. The hop chain is not the planner result.
  5. Closing headline "The network is ready." and Enter portal.
  6. A short factual strip: counts of detectors and attack types.
  7. Footer with the course name.
Portal (after login, route /portal):
 Shell: forest sidebar with text navigation, sand main area, top bar with user, role, seed, simulation state.
 Routes:
  Overview: 3D map (two thirds width), alert feed, stat strip, host panel on selection.
  Attack lab: pick type, source host, target host (click on the map or choose from lists), launch, watch the path
   animate, see the alerts the detectors raise, see the risk change. Presets: port scan, brute force, DoS flood,
   data transfer, and a staged "multi-stage attack" that runs three in sequence.
  Alerts: filter by severity, type, source, target. Click a row to focus the host on the map.
  Incidents: list with status, grouped alerts, timeline of one incident.
  Hosts: table and detail page with risk history chart, recent alerts, tasks assigned.
  Planner: run response; backbone drawn on the 3D map; assignment table by team; excluded tasks; state count.
   Algorithm trace (phase 2): step through Kruskal edge by edge, and show the DP result.
   What-if: remove the two highest risk hosts and rerun, compare before and after.
  Reports: preview, export as text.
  Admin (Admin role only): detector thresholds (read first, edit in phase 2), users (phase 2), event log viewer.
 Role gating mirrors the backend. Viewer cannot launch attacks or run the planner.

## 3D map
three + react-three-fiber. Ground plane in forest. Perspective camera, slight tilt, orbit controls with the polar angle
clamped and damping. Flat shading, no bloom, no glow, no gradients, no textures.
Nodes: server = two stacked boxes, workstation = flat box with a thin screen, router = cylinder, IoT = octahedron.
Colour from status. Height or ring size from risk. Links: thin tubes, red when compromised.
Layout is presentation only: a deterministic 3D force layout (seeded), computed once per topology and cached.
Picking by raycast. Hover swaps an outline colour instantly. Click focuses the camera (GSAP, 900ms) and opens the host panel.
Attack animation: a marker travels from source to target along the straight arc, 700ms, then the target ring pulses once.
Backbone: chosen links draw on one after another. Unreachable hosts get a dashed ring and a text label.
Use InstancedMesh above 50 nodes. Cap at 60 fps. Pause rendering when the tab is hidden.
Every 3D element also exists as text in the side panel, so the screen is usable without it.

## API (server, package web)
POST /api/login {username, password} returns {role}. The facade holds a single current user, so this is a
single-session demo. GET /api/network returns assets and links. POST /api/sim/start, /stop, /reset, /auto {on}.
POST /api/attacks {type, src, dst}. GET /api/alerts, GET /api/incidents.
GET /api/stream is Server-Sent Events: alert, asset and link changes, tick. A StreamBroadcaster implements AlertListener
and is subscribed through facade.addAlertListener (this keeps the Observer pattern).
POST /api/response/run returns the plan. GET /api/report returns text.
Phase 2 (spec change, needs a class-spec edit first): GET /api/response/trace, GET and PUT /api/config, GET /api/users.
All logic stays in Java. The client never recomputes detection, risk, Kruskal or DP.

## Quality bar
Usable at 1366x768. Keyboard reachable, visible 2px focus outline, semantic HTML.
No console errors. Lighthouse performance at least 80 on the landing page.
Empty states say something useful. Copy is short and factual: "Active alerts 12", "Risk score 72 of 100".
