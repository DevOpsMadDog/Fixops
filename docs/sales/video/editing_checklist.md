# Post-Recording Editing Checklist — ALdeci 5-Min Demo

**Editing tool:** Loom's built-in trim + chapters (sufficient for cuts only) OR Descript (recommended for captions, stat inserts, and annotation overlays in one pass).

---

## Step 1 — Review Before Any Editing

- [ ] Watch the full recording once at 1.0x speed with headphones — listen for stumbles, background noise spikes, and pacing dead zones (silence > 2 sec)
- [ ] Note timecodes of problems in the table below before touching the timeline

| Timecode | Issue | Action |
|----------|-------|--------|
| | | |

---

## Step 2 — Structural Cuts (do these first)

- [ ] **Remove any pre-recording dead air** at the start — cut everything before the first word of the Hook
- [ ] **Remove any post-recording fumble** at the end — cut everything after the "book 30 minutes" close line, before the logo frame
- [ ] **Remove filler pauses** longer than 2 seconds — exception: the intentional 1-sec pause after "$147,000" in Scene 2 and the pause after the 703 DPO stat in Scene 5 (these are intentional; see script). Do not cut those.
- [ ] **Remove any accidental navigation** — if you accidentally opened a wrong tab or wrong page during recording, cut those frames entirely
- [ ] **Remove the Assets page crash frame** (DEMO-BUG-001) if it appears — cut the error state, cut to the `04-assets-chokepoint.png` screenshot inserted as a chapter or image overlay. If you used the contingency line smoothly, you may keep the transition as a sign of confidence.

---

## Step 3 — On-Screen Text Inserts (add after structural cuts)

These stats must appear as on-screen text overlays — they are spoken in the voice-over but need visual reinforcement for viewers who watch without audio.

| Timecode (approx) | Text to insert | Style | Duration |
|---|---|---|---|
| ~2:00 (Brain consensus) | **703 DPO pairs learned from analyst overrides** | Lower-third, black bar, white 18px | 4 sec |
| ~0:45 (Score breakdown) | **$147,000 expected loss** | Callout box, yellow border | 3 sec |
| ~0:50 | **EPSS: 87% exploitation probability — 30 days** | Callout box, orange | 3 sec |
| ~1:05 | **Multi-LLM Council: 3 models. 85% threshold. Hard rule.** | Title card overlay | 4 sec |
| ~2:15 | **AutoFix: 10 fix types. HIGH confidence → auto-PR. Your data. Your model.** | Lower-third | 4 sec |
| ~3:00 | **FIPS 204 ML-DSA — post-quantum signatures** | Callout box, blue border | 3 sec |
| ~3:25 | **412 evidence events. Auto-generated. WORM. 7-year retention.** | Lower-third | 4 sec |
| ~4:15 | **$4.2M blast radius — 47 crown-jewel assets downstream** | Callout box, red | 3 sec |
| ~4:50 | **Federal SCIF: 20-day pilot path** | Split lower-third panel 1 of 3 | 2 sec |
| ~4:52 | **Mid-market: live today** | Split lower-third panel 2 of 3 | 2 sec |
| ~4:54 | **Investor demo: book 30 min** | Split lower-third panel 3 of 3 | 3 sec |

---

## Step 4 — Multi-LLM Council Voiceover Emphasis (audio edit)

The Brain Pipeline / Consensus section (1:30–2:45) carries the heaviest technical weight. If delivery was flat in the recording, apply a light EQ boost (+2 dB at 2–4 kHz) to the voice in this section only to increase perceived clarity and presence.

**Voiceover line to verify is audible and un-rushed:**
> "Watch as 5 models converge on a verdict. Each model votes independently — we require an 85% agreement threshold before a severity or remediation decision is emitted downstream."

If this line was rushed (under 7 seconds), slow the clip playback to 0.9x in Descript for this sentence only — the slight slow-down is imperceptible to the listener and improves comprehension.

---

## Step 5 — Captions and Subtitles

Captions are required — not optional:
- 60–85% of LinkedIn and email-embedded video views are watched without audio (mobile, open-plan office)
- FIPS, ML-DSA, MPTE, DPO, Edmonds-Karp, and CISA KEV are jargon terms that must be spelled correctly in captions — auto-generated captions will mangle them

**Process:**
1. Descript: auto-transcribe → correct the following terms manually:
   - FIPS → FIPS (not "FIPS" → "lips" or "fits")
   - ML-DSA → ML-DSA (not "ml dsa" or "emeldsa")
   - MPTE → MPTE (not "empty" — this is the #1 auto-caption failure)
   - DPO → DPO (not "depo" or "depot")
   - Edmonds-Karp → Edmonds-Karp
   - CISA KEV → CISA KEV
   - ALdeci → ALdeci (not "Al Desi" or "Al Decci")
2. Caption style: white text, black outline, bottom-center, 80% screen width max
3. Font: Inter or Helvetica Neue — not Comic Sans, not decorative fonts
4. Review captions at 1.0x speed in the final export before sharing

---

## Step 6 — Final Export Settings

| Setting | Value |
|---------|-------|
| Resolution | 1920×1080 |
| Frame rate | 30 fps |
| Format | MP4 (H.264) — maximum compatibility for email embeds and LinkedIn |
| Bitrate | 5–8 Mbps (Loom handles this automatically; Descript: "High quality" preset) |
| Audio | AAC 256 kbps, 48 kHz, stereo |
| Captions | Burned-in for LinkedIn/email distribution; separate .SRT file for CMS uploads |
| File size target | Under 200 MB for email attachment compatibility |

---

## Step 7 — Distribution Checklist

- [ ] Upload to Loom (primary shareable link for sales reps)
- [ ] Export MP4 + upload to HubSpot/Salesforce library with metadata: `ALdeci 5-Min Demo | juice-shop-corp | 2026-04-26`
- [ ] LinkedIn: upload natively (not YouTube link) — LinkedIn algorithm gives 3–5x organic reach to native video vs. external links
- [ ] Companion screenshot: attach `docs/ui-snapshots/demo_2026-04-26/01-command.png` as thumbnail override (Loom allows custom thumbnails; use the Command KPI strip — highest-information frame)
- [ ] Add CTA in Loom description: "Book a 30-min live demo → [calendar link]"
- [ ] Send to champion with subject line: "2 minutes — ALdeci doing what your team spent a week on"

---

## Quality Gates — Do Not Publish Until All Pass

| Gate | Pass condition |
|------|---------------|
| Runtime | 5:00–5:45 |
| Captions | All 8 jargon terms spelled correctly |
| 703 DPO stat | On-screen text insert present at ~2:00 |
| FIPS 204 line | Audible AND in captions — this is the federal hook |
| No mock data on screen | No `MOCK_`, `Acme Corp`, `lorem ipsum`, `John Doe` visible in any frame |
| No other browser tabs visible | Zero tabs showing in any frame |
| Asset Graph contingency | If crash frame is in recording, confirm it is either cut or covered by contingency overlay |
| Audio peaks | No clipping (red zone) in any frame; -12 dB to -6 dB average |
