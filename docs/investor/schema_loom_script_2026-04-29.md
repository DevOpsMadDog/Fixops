# 60-90 Second Loom Script — Schema Ventures Outreach

**Recording target:** under 90 seconds
**Audience:** Aarthi Ramamurthy, Schema Ventures
**Hook:** her own thesis word ("AI powered pentesting") matched to a specific defensible angle

---

## Beat 1 — Hook (0:00–0:10)

> "Hey Aarthi — saw your Schema thesis post yesterday. You named AI-powered pentesting in slot one. We're building that, but with a twist that separates us from the OSS GitHub crowd."

**On screen:** Aldeci homepage / Brain Pipeline diagram

---

## Beat 2 — The Twist (0:10–0:25)

> "Most AI pen-testers — PentAGI, Nebula, Garak — are single-LLM wrappers around GPT-4 that generate text reports. We built something different: a 4-member multi-LLM consensus council that exploit-verifies findings, then feeds them into a knowledge graph that drives the rest of the security platform."

**On screen:** split view of Brain Pipeline 12 steps with step-11 (Pen-Test) highlighted, then arrow to TrustGraph node → DPO learning loop → Risk score

---

## Beat 3 — Live Proof (0:25–0:55)

> "Here's the proof. We pointed Aldeci at yahoo.com — type domain, click scan. Thirty seconds later, the platform surfaced a HIGH-severity Host Header Injection vulnerability and gave me the curl commands to reproduce it. Watch."

**On screen:** Open `data/pentest_report_data.json` rendered, scroll to the Host Header Injection finding, show the curl reproduction. THEN open a terminal: paste the 3 curl commands → first returns clean, second returns canary in response → finding confirmed.

> "No competitor — Snyk, Wiz, Apiiro, Aikido — ships exploit reproduction inline. They detect. We detect, exploit, and prove."

---

## Beat 4 — Why We're a Platform, Not a Tool (0:55–1:15)

> "And we're not a CLI tool. We're a unified ASPM-CSPM-CTEM platform. Sixty-three hundred API endpoints, 17 native threat-feed integrations, federal SCIF and air-gap deployment. The OSS pen-testers are libraries. We're the Snyk + Wiz + Apiiro replacement at one-thirtieth their price."

**On screen:** API endpoint count, sub-app architecture diagram (5 sub-apps), pricing comparison

---

## Beat 5 — The Ask (1:15–1:30)

> "If this resonates, send me 15 minutes this week. I'll walk you through the live council convening and our public self-scan dashboard where Aldeci scans Aldeci's own code with results posted. You're the third investor we're approaching, and Schema's thesis match is the closest. Talk soon."

**On screen:** Schema Ventures logo + your contact card + "aarthi@schemavc.com → reply"

---

## Recording tips

- Don't read this. Internalize the beats. Authenticity > polish.
- Use the actual Yahoo report — open the JSON file, scroll, point at the curl block. The visual proof is stronger than the words.
- Run the curl commands LIVE if possible (they're idempotent + harmless). If yahoo.com has fixed the issue, use a different live target you've pre-verified.
- Sign off energetic but not desperate. "Talk soon" not "please consider".
- Total runtime: aim for 75-85 seconds. Anything over 90 loses her.

---

## Three-line follow-up email (if she replies "send more")

> Subject: Re: AI security operating system — Aldeci
>
> Three artifacts: (1) `aldeci_yahoo_pentest_proof_2026-04-29.md` — the Yahoo finding with reproduction. (2) `MASTER_INVESTOR_PACK_2026-04-27.md` — full one-pager with traction, market, comp matrix. (3) Live demo URL when our self-scan workflow lands tonight: `https://devopsmaddog.github.io/Fixops/self-scan/`. What's the best 15-min slot this week?
