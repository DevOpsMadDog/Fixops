# Solo Recording Setup — ALdeci 5-Min Demo

**Tool recommendation: Loom over OBS.**
Reason: Loom captures mic + screen simultaneously, auto-uploads, generates a shareable link in under 60 seconds after recording ends. OBS requires manual encoding + upload and is optimized for streaming rather than async sales videos. Use OBS only if you need local-only output for a classified environment.

---

## Pre-Recording Checklist (do all of this before pressing Record)

### Browser
- [ ] Browser: Chrome (not Safari — Chrome dev tools network tab matches `network_trace.json` evidence format)
- [ ] Zoom level: **100%** (Cmd+0 to reset) — UI was designed and screenshotted at 100%; any other zoom shifts pixel grid and misaligns annotation overlays
- [ ] Resolution: **1920x1080** — if your display is HiDPI/Retina, set Loom to record at 1920x1080 logical pixels; Loom handles the retina scaling automatically
- [ ] Single window, single tab — no other tabs open
- [ ] Browser theme: **Chrome default light** — dark mode causes UI contrast issues on some compliance badge colors
- [ ] Address bar hidden: enter full-screen presentation mode (F11 / Cmd+Shift+F) or use a browser frame hide extension
- [ ] Bookmarks bar: **hidden** (Cmd+Shift+B to toggle)
- [ ] Browser notifications: **disabled** — System Preferences → Notifications → Chrome → off. Do this now, not 5 seconds before recording.
- [ ] No desktop notification banners: macOS → Do Not Disturb → ON for duration of recording

### Pre-load the tenant
- [ ] Run: `curl -s http://localhost:8000/api/v1/health` — confirm 200 before opening browser
- [ ] Open `http://localhost:5173/command` — wait for KPI strip to fully load (all 4 tiles populated, no spinners)
- [ ] Verify KPI values: Findings ≥ 1,000 | Open Critical > 0 | MPTE-verified exploitable > 0
- [ ] If any tile shows 0 or spinner: run `scripts/onboard_real_apps.sh juice-shop-corp` and wait 90 sec, then reload
- [ ] Fallback tenant `node-goat-inc` already onboarded and available if juice-shop-corp KPIs are blank
- [ ] Pre-navigate to each hero URL and let it load, then use browser history to snap back to `/command` before pressing Record — page renders faster on second visit

### Desktop
- [ ] Desktop background: solid dark color (no family photos, no other apps visible in window gaps)
- [ ] Close all unrelated apps — Slack, Mail, Calendar, Finder windows, Spotify
- [ ] Dock: auto-hide (System Preferences → Dock → Automatically hide and show the Dock)
- [ ] Clock: hide or move off primary display — you do not want "4:37 PM" visible in the recording
- [ ] Screensaver: disabled for duration

### Screen setup
- [ ] Single display recording — disconnect external monitors or explicitly tell Loom to record the primary display only
- [ ] Browser window: maximized (not full-screen — you need the address bar visible briefly for credibility when navigating; full-screen hides it entirely)
- [ ] If you have a notch (MacBook 14/16): set browser window to leave 38px of menu bar visible — Loom's notch handling is inconsistent

---

## Mic Setup

### Hardware
- Recommended: USB condenser mic (Blue Yeti, Rode NT-USB, or equivalent). Built-in MacBook mic is acceptable but will pick up keyboard and fan noise.
- Position: mic 6–8 inches from mouth, slightly off-axis (45 degrees) to reduce plosives on "p" and "b" sounds.
- No headphones required if using a directional mic in cardioid pattern — feedback is not a risk.

### Software
- **Noise gate**: In Loom audio settings, enable "Noise cancellation" (Krisp-powered in Loom Business). If using OBS: add a Gate filter, close threshold -40 dB, open threshold -30 dB, attack 5ms, hold 50ms, release 100ms.
- **Gain**: Speak normally and check Loom's input meter — peaks should hit -12 dB to -6 dB (yellow zone), never red. Reduce gain if you are consistently peaking above -6 dB.
- **Room**: Close doors. Hard surfaces (brick, glass) cause reverb — hang a blanket or sit close to a bookshelf for damping if you are in a bare room.

### Loom audio settings
1. Loom → Settings → Audio
2. Microphone: select your USB mic (not "Default")
3. Noise cancellation: ON
4. Record system audio: OFF (no accidental notification pings in the recording)

---

## Loom Configuration

### Version: Loom Business or Enterprise
Free tier caps at 5 minutes — your target is 5:00–5:30. Use Business tier ($15/mo) or Enterprise SSO.

### Settings before recording
1. Capture mode: **Screen + Camera** (camera off — this is a UI walkthrough, not a talking head)
   - Exception: if recording for a warm enterprise prospect, enable camera bubble (bottom-right corner, 120px) for the Hook (0:00–0:30) and Close (4:45–5:00) beats. Disable for the technical middle.
2. Recording area: **Full screen** (the browser window, not a region — region recording misaligns if you accidentally move the window)
3. Resolution: 1920×1080 (Loom auto-detects from display settings)
4. Frame rate: **30 fps** — 60 fps is overkill for a sales walkthrough and doubles file size
5. Quality: HD (720p minimum — 1080p preferred for compliance badge legibility)

---

## Pacing and Runtime

| Section | Target time | Hard limit |
|---------|------------|------------|
| Hook | 0:30 | 0:40 |
| Command hero | 1:00 | 1:15 |
| Brain hero | 1:15 | 1:30 |
| Compliance hero | 1:15 | 1:30 |
| Asset Graph teaser | 0:45 | 0:55 |
| Close | 0:15 | 0:20 |
| **Total** | **5:00** | **5:30** |

If you exceed 5:30 in your first take: cut the Asset Graph section to 30 sec (skip the blast-radius tab, go straight to the chokepoint visual and one sentence). Do not cut the 703 DPO stat or the FIPS 204 line — those are the two highest-signal differentiators.

Target: 5–7 min with edits. Avoid exceeding 10 min — engagement drops sharply after 7 min for cold outbound; after 10 min you have lost the next rep in the distribution chain.

---

## Take Strategy

- Take 1: treat as a rehearsal. Do not stop if you stumble — keep going. Review the full recording before deciding to re-record.
- Takes 2–3: if Take 1 had a single bad section, use Loom's trim tool to cut and re-record that chapter only (Loom chapters feature). Do not re-record the full 5 minutes for a 10-second stumble.
- Maximum 3 full takes in a session — fatigue degrades delivery more than imperfect phrasing.
- If the Assets page crashes (DEMO-BUG-001): do not stop recording. Say the contingency line from `5min_demo_script.md`, switch to the static screenshot, continue. This is more credible than a re-recorded take that avoids the page entirely.
