# Zach panel design

Canonical source: [ZACH-030, issue63](https://github.com/shockerqt/zach/issues/63), approved visual design2026-11-12. Original SVG/desktop/mobile design-canvas assets preserved byte-for-byte; references are design source, not executable app.


Dark operations panel; the black cat sits in front of a pale moon so it stays legible on a dark ground. Two accents only: amber (brand, attention, the cat's eyes) and blue (healthy/active). Failure is orange and always paired with an icon or text, never colour alone.

### Tokens

| Token | Value | Use |
|---|---|---|
| ground | `#121316` | page background |
| panel | `#1A1C20` | cards |
| line | `#2A2D33` | card borders, dividers |
| line-strong | `#3A3E46` | button and input borders |
| text | `#ECEAE4` | primary text |
| text-2 | `#C9CCD3` | secondary text, section headings |
| text-3 | `#A3A6AD` | metadata (minimum contrast 4.5:1 on panel) |
| amber | `#F0C94A` | task ids, decision card border, primary button (text `#17150C`) |
| blue | `#7FB2FF` | daemon alive dot, focus ring |
| fail | `#FFA98C` on `#2A1A15`, border `#8A4630` | failed stage, stopped merge lane |
| now | `#F0C94A` on `#2A2510` | stage waiting on the operator |
| moon | `#F3E4A4`, craters `#E6D48C` | mascot backdrop |
| cat | `#0E0E10` | mascot body |

Type: Space Grotesk 600/700 for headings and the wordmark, Inter 400/500/600 for body (14px desktop, 15px phone), JetBrains Mono for task ids, SHAs and timestamps. Radius: 16px cards, 10px controls, 999px chips. Touch targets at least 44px high; primary decision buttons 48px (52px on phone).

### Layout

- **Header**: mascot (36px) + wordmark; chips for daemon heartbeat, slots in use, one chip per provider (quota exhausted is the fail style with a warning icon); `Pausar cola` button and a mute toggle.
- **Left column (320-380px)**: mascot at 200px with a one-line status sentence, then the decision card (amber border): kind, task id and weight, the question, context, link to plan/review, optional note input, `Aprobar` (amber, filled) and `Rechazar` (outline).
- **Centre (fluid)**: `En curso`, one card per task with a stage track (one cell per required stage: done = check, failed = cross, waiting on operator = filled dot in amber, pending = ring) showing model and duration per stage; a status line with actions when the task is stuck (`Reintentar merge`, `Ver PR`). Below it `En cola` with the reason each task is waiting.
- **Right column (300-380px)**: `Cola de merge` per repository with lane state, then `Eventos` (time, event, task and detail) fed by SSE.
- Columns wrap: at phone width the order is decision, tasks, merge queue, events. The phone layout puts the decision card first with full-width buttons.

### Mascot states

One SVG, one visible layer set per state. Transitions: cross-fade eye layers over 200ms; tail sways slowly while hunting; respect `prefers-reduced-motion`.

| State | Layers shown | Trigger |
|---|---|---|
| idle (Siesta) | `eyes-nap` | no task in progress |
| hunting (Cazando) | `eyes-wide` | `STAGE_STARTED` plan or impl |
| review (Monóculo) | `eyes-open` + `monocle` | `STAGE_STARTED` plan-review or pr-review |
| decision (Atento) | `eyes-open` + `badge-decision` | any open decision (highest priority) |
| merged (Ronroneo) | `eyes-happy` | `MERGE_COMPLETED`, held for a few seconds |
| error (Erizado) | `eyes-narrow` | failed stage, `MERGE_FAILED`, blocked lane |
| paused (En pausa) | `eyes-nap` + `badge-paused` | queue paused by the operator |

Priority when several apply: decision, error, paused, review, hunting, merged, idle.


## Behavior and accessibility

Fetch /api/snapshot once, then authenticated fetch SSE from /api/events with sequence replay/reconnection and no polling. Decisions POST /api/decide with exact server choice and optional note; disable pending buttons and show ALREADY_RESOLVED honestly. Sound (decision chirp/merge purr) off by default and only after explicit operator enablement. At390px no horizontal scrolling, decision first, everycontrol44px minimum. Semantic labelled buttons/links/inputs, textcontrast4.5:1 minimum. Fonts locally bundled. Sessionbearer in memory only; browser-managed same-origin Access cookie remains outer identitygate. Respect unavailable backend data/actions; do not fabricate quota, pause or historical timing.

## Asset provenance

Three source files extracted verbatim from canonical issue fenced blocks, without decoding entities, formatting or repair. ExactSHA256:

{
  "zach-mascot.svg": {
    "sha256": "6937180c36a1d1c6ca042e406a75a0606e277eb4adbd3f9f398d68b261fb7252",
    "bytes": 3162
  },
  "desktop-reference.html": {
    "sha256": "736016fcf2430bbebe5780c43871755d8b3cb62cc6022ca2ddb3133f180a8af6",
    "bytes": 14129
  },
  "mobile-reference.html": {
    "sha256": "32f009a0950da56ef5960c3016552f058104f085dd3d2971fc9f5ced037166bf",
    "bytes": 4915
  }
}


Additional telemetry-map references in the issue remain gated by separate issue66; not part of this panel.
