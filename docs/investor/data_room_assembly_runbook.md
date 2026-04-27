# ALdeci Investor Data Room — Assembly & Sharing Runbook

**Owner:** Marketing Head / Founder  
**Last updated:** 2026-04-26  
**Script:** `scripts/build_investor_data_room.sh`

---

## 1. When to Refresh the Data Room

| Trigger | Action |
|---------|--------|
| New traction milestone (DPO pairs, test count, onboarding results) | Re-run script, update `TRACTION_METRICS` doc, rebuild bundle |
| Competitor move (funding, new feature, acquisition) | Update relevant battle card, re-run script |
| Architecture change (new scanner, new engine, new router) | Update `CTEM_PLUS_IDENTITY.md` and `ALDECI_REARCHITECTURE_v2.md`, rebuild |
| New SCIF/FedRAMP milestone (control met, POAM item closed) | Update `docs/scif/` files, rebuild |
| Investor meeting scheduled | Always rebuild 24 hours before — never share a stale bundle |
| New pitch deck version | Replace in `docs/pitch/`, rebuild |
| Pre-close legal docs ready | Replace `08_legal_ip/README.md` placeholder with VDR link |

Rebuild command:
```bash
bash scripts/build_investor_data_room.sh 2026-04-26
```

---

## 2. How to Share

### Option A — Dropbox (preferred for US investors)
1. Upload `dist/aldeci_data_room_2026-04-26.tar.gz` to a **private** Dropbox folder
2. Generate a password-protected shared link (Dropbox Business → Share → Set password)
3. Send the password separately from the link (different channel — e.g., link via email, password via SMS or WhatsApp)
4. Set link expiry: 14 days for first share, 30 days for active diligence
5. Enable "notify me when accessed" — track opens

### Option B — Google Drive (preferred for international investors)
1. Upload the `.tar.gz` to a Drive folder with "Restricted" sharing
2. Share with investor's email directly — do NOT use "Anyone with link"
3. Enable download tracking via Drive activity log
4. For large diligence rooms, use Google Workspace Shared Drive with viewer-only permissions

### Option C — Dedicated VDR (for serious diligence, pre-term-sheet)
Recommended platforms: Docsend, Carta (Series A standard), Box (enterprise buyers)
- Docsend: page-level analytics, NDA gate, watermarking
- Send individual folder links per section, not the full room at once
- Gate section 08_legal_ip behind NDA execution

### Sharing Protocol
1. Execute or confirm NDA before sharing anything beyond the one-pager
2. Track every recipient in a CRM (name, firm, date shared, version hash)
3. Include the manifest SHA-256 in your email: "Integrity hash: `<first 16 chars of manifest>`"
4. Never share the raw `dist/` directory from GitHub — always the packaged `.tar.gz`

---

## 3. What to Redact Before Sharing

Run this checklist before every external share. The script does NOT auto-redact — this is a human step.

### Must Redact / Remove
- [ ] API keys, tokens, secrets — grep: `sk-`, `AKIA`, `Bearer `, `password =`
- [ ] Named design-partner or customer data — any company name that is not publicly announced
- [ ] Personal contact information — emails, phone numbers, home addresses
- [ ] Unexecuted term sheets or LOIs
- [ ] Cap table specifics (share counts, option pool %) — share only post-NDA with lead investor
- [ ] Internal salary figures or compensation details
- [ ] Source code files — architecture docs only, never `.py` / `.ts` files
- [ ] Internal Slack / linear / Jira links that expose internal tooling
- [ ] SwarmClaw / OMC / agent scaffolding internals — those are operational, not investor-facing
- [ ] Federal sponsor names in `target_list_2026-04-26.md` — replace with tier descriptions (P1 DoD agency, P2 IC agency) unless sponsor has given explicit permission to name them

### Review Before Each Share
- [ ] SCIF readiness doc — confirm the maturity percentages are current (do not overstate)
- [ ] Traction metrics — confirm DPO pair count and test count match live `data/learning_signals.db`
- [ ] Competitor deep-dives — flag any claims about competitor pricing that are >90 days old
- [ ] Battle cards — confirm no invented feature claims; all claims must trace to a doc in `docs/`

### Safe to Include As-Is
- All docs in `docs/scif/` (written for auditor consumption, no secrets)
- All docs in `docs/sales/battle_cards/` (competitive intel, public information)
- `CTEM_PLUS_IDENTITY.md` and `ALDECI_REARCHITECTURE_v2.md` (architecture references, no code)
- `NIST_800-53_control_matrix` CSV (compliance posture, no sensitive detail)
- Placeholder READMEs in `07_team/` and `08_legal_ip/`

---

## 4. Version Control of Bundles

- The `dist/` directory is gitignored — bundles are never committed
- The **script** is committed (`scripts/build_investor_data_room.sh`)
- The **manifest** is committed after each build: `git add dist/*.manifest.sha256`
- Tag each shared version: `git tag data-room-v1-2026-04-26` after first external share
- Keep a local archive of every `.tar.gz` shared; label by investor and date

---

## 5. Integrity Verification

Recipients can verify the bundle was not tampered with:

```bash
# Unpack
tar -xzf aldeci_data_room_2026-04-26.tar.gz

# Verify all files match the manifest
cd data_room_2026-04-26
sha256sum --check ../aldeci_data_room_2026-04-26.manifest.sha256
```

All lines should output `OK`. Any `FAILED` line indicates file modification after signing.

---

## 6. Refresh Frequency Targets

| Audience | Refresh cadence |
|----------|----------------|
| Cold outreach (first touch) | Build once per sprint (2 weeks) |
| Active diligence | Rebuild before every meeting |
| Lead investor (term sheet stage) | Daily rebuild available on request |
| VDR for closing | Freeze at signing; final manifest is the legal artifact |

---

*Runbook owner: Marketing Head. Questions: ping in #investor-ops Slack.*
