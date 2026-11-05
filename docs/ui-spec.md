# UI spec

Applies to the Swing app and to the web pages. Both use the same tokens.
Identity: a quiet field-station console. Forest green and sand. Flat, dense, factual.

## Banned (never generate any of these)
- Purple-to-blue gradients, any gradient at all, gradient text
- Grain or noise textures, glassmorphism, blur, translucent cards, glow shadows
- Emoji anywhere, including headings and buttons
- Inter, Space Grotesk, Instrument Serif, serif italics for accent words
- Lucide, Feather or any icon library used everywhere
- Cards with a coloured left border
- Three icon boxes in a row, feature grids
- A badge or pill above a headline, hero sections
- shadcn, Tailwind defaults, or any component library left in its default look
- Fade-in on scroll, a beam or glow that follows the cursor
- Hover effects that fade buttons: hover is an instant colour swap
- Em dashes (the character U+2014) in UI text, comments or docs. Use a comma, colon or full stop.
- Buzzword copy: seamless, powerful, next-generation, AI-powered, insights, supercharge, unlock
- Low-contrast text. Every text pair must be at least 4.5:1, body text at least 7:1.

## Colour tokens (use only these)
Ground (sand)        #E8DCC4   page background
Surface              #F3ECDD   tables, panels
Line                 #C9BA9A   1px borders and row rules
Ink (forest)         #1F3D2B   text and primary buttons
Ink muted            #4A5E4F   secondary text
Forest ground        #1F3D2B   sidebar, network map background
Forest raised        #2A4F39   hover and selected rows on forest
Forest line          #3E6650   rules on forest
Sand on forest       #E8DCC4   text on forest ground
Muted on forest      #B9C4B3   secondary text on forest

Status on sand (always with a text label):
 normal #2F6B45   suspicious #7A4F08   compromised/critical #A8321F   low #3F6182
Status on forest (map nodes and links):
 normal #8FBF9F   suspicious #E0A63B   compromised/critical #E5604D   low #8DB1D6

There is no separate accent colour. Primary buttons are forest fill with sand text.
Selected navigation item is sand fill with forest text.
Status colours mean status and nothing else.

## Type
Text: IBM Plex Sans (400, 600). Data (IPs, times, scores, counts): IBM Plex Mono.
Scale: 12, 13, 14, 16, 20, 28. Body 14. Sentence case everywhere, no letterspaced caps.
Self-host the fonts (resources/fonts), no CDN.

## Spacing and shape
Base unit 4px. Allowed values: 4, 8, 12, 16, 24, 32, 48. Nothing else.
Corner radius 4px or 0. 1px borders. No shadows.
Layout works at 1366x768.

## Icons
No icon library. Four asset glyphs drawn in code with a 1.5px stroke:
 server = rounded rectangle with two lines, workstation = rectangle on a small base,
 router = circle with four short lines, IoT device = small diamond.
Everything else is a text label.

## Screens
Shell: forest sidebar on the left (text navigation: Monitor, Alerts, Control, Planner,
Report, Admin), sand main area. Admin is shown only to the Admin role.

Login: one form column 320px wide on the sand ground. Title "Network Threat Detection",
fields Username and Password, button "Sign in". No logo, no hero, no tagline.

Monitor:
 - A single strip of four figures separated by 1px vertical rules, no boxes, no icons:
   Hosts | Active alerts | Hosts compromised | Links compromised.
   Figure in Plex Mono 28, label in 12 below it.
 - Network map on forest ground, the dominant area (about two thirds of the width).
 - Alert feed to the right: a table with row rules. Columns: Time, Severity, Type,
   Source, Target. Severity is the word plus an 8x8 square of the status colour.
 - Host panel: a plain definition list (Name, IP, Type, Risk, Status, Last alert).

Control: buttons "Port scan", "Brute force", "DoS flood", "Data transfer";
 "Start traffic"/"Stop traffic"; a Manual/Auto segmented switch; "Reset". One primary
 button per screen, the rest bordered.
Planner: "Run planner" button, backbone drawn over the map, assignment table below.
Report: monospace preview and an "Export report" button.

## Copy
Short, factual, no marketing voice. Examples of correct text:
 "Active alerts", "Risk score 72 of 100", "No alerts. Start the traffic.",
 "Planner: 14 links kept, 2 hosts unreachable", "Access denied for role Viewer".

## Motion (state changes only, ease-out, no bounce)
 - Node colour change: blend over 300ms
 - Host becomes compromised: one ring grows and fades, 600ms, once
 - Link becomes compromised: colour blend 300ms
 - New alert row: background tint fades out over 800ms
 - Planner backbone: links draw on from one end, 500ms
No other animation. No hover transitions. No page, tab or scroll transitions.
One shared 16ms timer, stopped when nothing is animating.
Cap rows added to the alert feed at 10 per second and group the rest as
"+N similar alerts". Painting and animation stay on the Swing thread.

## Implementation rules
Swing: FlatLightLaf with the theme file in ui/theme, custom painted map with antialiasing,
no gradients in any paintComponent. Web: hand written CSS in one file with CSS variables
for the tokens above, semantic HTML, CSS grid, SVG map, visible 2px focus outline.
No logic in the UI. Call IncidentResponseFacade only.
