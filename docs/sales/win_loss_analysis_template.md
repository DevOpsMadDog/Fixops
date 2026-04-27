# Win/Loss Analysis Template

> **Trigger:** Deal closed (won) OR deal closed (lost) OR POC terminated.
> **Interviewer:** NOT the AE who owned the deal — bias risk too high. Use Sales Engineer from a different territory, or Customer Success lead.
> **Format:** 30-minute video call. Recorded with consent. Notes captured below.
> **Cadence:** Within 14 days of close. Sooner = sharper memory.
> **Storage:** `.claude/team-state/sales/win-loss/{customer-slug}-{won|lost|terminated}-{YYYY-MM-DD}.md`

---

## Pre-interview prep (interviewer fills before call)

| Field | Value |
|-------|-------|
| Customer org | |
| Industry / vertical | |
| Employee count | |
| Annual revenue | |
| Initial ACV proposed | |
| Final outcome | WON / LOST / TERMINATED-MID-POC |
| If WON: tier + ACV | |
| If LOST: which competitor (if any) | |
| If TERMINATED: at which day of POC + reason given on D14 call | |
| AE on the deal | |
| SE on the deal | |
| Length of sales cycle (first contact → close) | __ days |
| Number of stakeholders involved | |
| POC ran? | YES / NO |
| If yes, POC scorecard result | __/5 |

---

## 12 interview questions

### Discovery & evaluation (Q1–Q4)

**Q1. How did you first hear about ALdeci?**
- Probe: outbound from us / inbound from your search / referral from {who} / event / analyst report / Reddit / LinkedIn / Google / vendor RFP

**Q2. When you were evaluating ALdeci, what other tools were on your shortlist? Who made the cut?**
- Probe: Snyk / Apiiro / Wiz / Tenable / XM Cyber / Aikido / Sonatype / something else / nothing else

**Q3. What were the top-3 evaluation criteria you used to score vendors?**
- Probe: price / breadth / depth on one capability / deployment model / specific compliance / specific integration / time-to-value / our team's reputation

**Q4. Where did ALdeci rank against your top-3 criteria? What surprised you (good or bad)?**
- Probe: was anything different from how we positioned in discovery?

### Decision & competitor (Q5–Q8)

**Q5 (WON). Which competitor did we beat, and what was the deciding factor?**
- Probe: did they offer the same on the deciding factor and we just won on price/relationship, or did we genuinely have something they didn't?

**Q5 (LOST). Which competitor did we lose to, and what was the deciding factor?**
- Probe: was it a capability gap, a pricing gap, a deployment-model gap, a relationship gap, or a "they got there first" gap?

**Q6. Was there a moment in the cycle where you were leaning toward a different decision than the one you made? What flipped you?**
- Probe: which demo beat / which conversation / which artifact moved the needle

**Q7. How did pricing factor in? Was the published tier ($199 / $499 / $1,499) at, above, or below your expectation?**
- Probe: did you ask for a discount? did you get one? would you have signed without it?

**Q8. Which of our claims in the demo or POC did you find least credible? Why?**
- Probe: be specific — "Multi-LLM consensus", "MPTE verification", "quantum-safe evidence", "12-step pipeline", "self-learning loop"

### Deployment & time-to-value (Q9–Q10)

**Q9 (WON or POC-completed). How long did it take from "first finding ingested" to "first decision your team trusted"?**
- Probe: was that fast enough? what slowed it down?

**Q10. Was there friction in deployment / connector wiring / SSO setup that nearly killed the deal?**
- Probe: which integration was hardest? what would have made it easier?

### Recommendation (Q11–Q12)

**Q11. On a 0–10 scale, would you recommend ALdeci to a peer at another company in your industry? Why that number?**
- Probe: what would have to be true for you to give us a 10?
- This is our NPS-equivalent for win/loss. Track it.

**Q12. What's the one thing we should change about how we sell, demo, or deploy that would have made your decision easier?**
- Probe: this is the gold question. Push for specificity.

---

## Scoring rubric (interviewer fills post-call, sales lead triages)

### Severity scoring

For each issue surfaced in the interview, score:

| Dimension | 1 (low) | 3 (medium) | 5 (high) |
|-----------|---------|------------|----------|
| **Frequency** — how often does this come up in our cycles? | One-off | Sometimes | Every deal |
| **Impact** — does this directly cause loss / delay / churn? | Indirect | Sometimes decisive | Almost always decisive |
| **Fixability** — can we fix in <90 days? | No (heritage moat / structural) | Yes with effort | Yes with prioritization |

**Issue priority = Frequency × Impact × (Fixability / 5)**.
Range: 1 (defer) → 75 (drop everything and fix).

### Triage categories

After scoring, route each issue to one of:

- **Product (capability gap)** — ship to Product Manager; goes into next-sprint backlog
- **Engineering (deployment friction)** — ship to platform engineer; usually script/installer fix
- **Sales motion (positioning gap)** — ship to Sales lead + Marketing; update battle cards / objection handling
- **Pricing (commercial gap)** — ship to AE leadership + CFO; possible tier rework
- **Documentation (clarity gap)** — ship to Technical Writer; update docs
- **Defer (heritage moat / structural)** — note in `docs/sales/competitive_gaps_we_accept.md`; do not ship

### Aggregation cadence

- **Per deal:** interviewer files within 7 days of call
- **Monthly:** Sales lead aggregates last 30 days of interviews; flags any issue with priority ≥ 25
- **Quarterly:** company-wide review of win/loss themes; presented to leadership; informs roadmap

---

## Post-interview follow-up (interviewer responsibilities)

- [ ] File interview notes in `.claude/team-state/sales/win-loss/`
- [ ] Score every issue surfaced; assign category
- [ ] Notify AE + SE who owned the deal (without judgment — this is learning, not blame)
- [ ] If priority ≥ 25 issue surfaced: tag the right team in Slack within 24 hours
- [ ] Send thank-you to interviewee; offer them a $50 charity donation in their name (or branded swag if WON)
- [ ] Update battle card for relevant competitor if competitor was named
- [ ] If WON and customer is referenceable: queue case-study request for D60

---

## Quarterly aggregate template

```
ALDECI WIN/LOSS QUARTERLY — Q_ FY____

Deals closed: ___ (___ won / ___ lost / ___ POC-terminated)
Win rate: ___%
Average sales cycle: ___ days
Average ACV (won): $______

Top-3 reasons we WON (cited in ≥3 interviews):
  1. _________________
  2. _________________
  3. _________________

Top-3 reasons we LOST (cited in ≥3 interviews):
  1. _________________
  2. _________________
  3. _________________

Top competitor faced: _________________ (___ deals)
  - W/L vs them: ___/___
  - When they win: _________________
  - When we win: _________________

Top NPS-recommend score: ___ (median across interviews)
Top issue priority: ___ (action: _________________)

Roadmap implications: _________________
Sales motion changes: _________________
Pricing implications: _________________
```
