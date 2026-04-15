# ALDECI Go-To-Market Strategy

## 1. Ideal Customer Profile (ICP)

### Primary ICP: Mid-Market Security-First Company
- **Company Size:** 50-500 employees
- **Revenue:** $5M-$50M ARR
- **Security Team:** 1-3 people (CISO, Senior Security Engineer, or both)
- **Cloud Infrastructure:** AWS, Azure, GCP, or hybrid
- **Compliance:** SOC2, HIPAA, PCI-DSS, or ISO 27001 required
- **Pain Points:**
  - Currently spending $50K-$100K/year on fragmented tools
  - Alert fatigue (5,000+ alerts/day, 96% false positives)
  - Compliance evidence collection is manual
  - Can't hire enough security engineers to manage tool sprawl
  - Data residency requirements (can't use cloud-only solutions)

### Secondary ICP: MSSP (Managed Security Service Provider)
- **Company Type:** MSP with security services practice
- **Client Portfolio:** 20-100 mid-market customers
- **Current Tools:** Reselling Snyk, Lacework, Rapid7 (complex, expensive, can't white-label)
- **Pain Points:**
  - Managing 50+ separate cloud SaaS subscriptions (billing nightmare)
  - No API-first platform for automation
  - Can't offer customers unified dashboard
  - Margins eroded by vendor costs ($200K/year in tool costs for 50 customers)

### Tertiary ICP: Enterprise with Downsize Mandate
- **Company Size:** 1,000-10,000 employees
- **Security Team:** 10+ people (mature SOC)
- **Current Spend:** $500K+/year on Wiz, Lacework, Snyk, Rapid7, Tenable
- **Trigger:** Board mandate to reduce security spend 40% YoY
- **Pain Point:** Must maintain coverage while reducing tool costs

---

## 2. Personas (Who Buys, Who Uses, Who Influences)

### Persona 1: Sarah Chen, CISO / VP Security (Economic Buyer)
- **Title:** CISO or VP Engineering (security-minded)
- **Company Size:** 50-500 employees
- **Motivation:**
  - Wants consolidated dashboard for board metrics (risk posture, KPIs, compliance status)
  - Needs evidence artifacts (SOC2, HIPAA, PCI) for audit
  - Wants to reduce security tool sprawl
  - Needs SLA auto-escalation (no more slow incident response)
- **Buying Process:** Takes approvals from CFO (cost) and CTO (technical fit)
- **Sales Cycle:** 4-8 weeks (tight decision)
- **Deal Size:** $1,188-5,988/year (easily approved under $10K)
- **Win Message:** "One platform instead of five. $1,188/year instead of $50K. Compliance ready on day one."

### Persona 2: Alex Rodriguez, Senior Security Engineer (Champion & User)
- **Title:** Security Engineer, Security Architect, or DevSecOps Engineer
- **Company Size:** 50-500 employees
- **Motivation:**
  - Wants API-first platform (can build custom workflows, no vendor lock-in)
  - Needs self-hosted (on-prem, air-gapped networks, data residency)
  - Wants to automate the alert queue (tired of manual work)
  - Wants to understand *why* an alert fired (context, not just risk score)
- **Buying Process:** Influences Sarah (CISO) on technical requirements
- **Sales Cycle:** 2-4 weeks (evaluates on GitHub, reads API docs, does PoC)
- **Deal Size:** $99-499/month Pro tier (own departmental budget)
- **Win Message:** "771 APIs. SCIM, Slack, Jira, n8n integration. Deploy in 15 minutes. No vendor lock-in."

### Persona 3: Marcus Johnson, SOC Analyst T1 (End User)
- **Title:** Security Operations Center (SOC) Analyst, Tier 1 or 2
- **Company Size:** 50+ employees
- **Motivation:**
  - Wants alert queue cleared (reduce false positives by 30-40%)
  - Wants context on alerts (why is this a risk? what else is affected?)
  - Hates context-switching between tools
  - Wants runbooks for common incidents
- **Buying Process:** Influenced by Alex (tech lead), but feedback loop to Sarah (CISO)
- **Sales Cycle:** N/A (Marcus doesn't buy, but his satisfaction drives renewal)
- **Deal Size:** N/A
- **Win Message:** "30% fewer false positives. One dashboard for everything. Clear incident context."

### Persona 4: Jennifer Park, MSSP Partner (Strategic Buyer)
- **Title:** VP Sales / VP Delivery at MSSP
- **Company Size:** 20-100 employees (MSSP), 50-100 mid-market customers
- **Motivation:**
  - Wants to white-label ALDECI for customers (new revenue stream)
  - Needs APIs for customer automation (reduce manual ticket creation)
  - Wants to improve margins (ALDECI is 10x cheaper than Wiz + Snyk bundle)
  - Wants to enable customer consolidation (ASPM + CTEM + CSPM in one)
- **Buying Process:** Needs technical evaluation (Alex-type engineer at MSSP does PoC)
- **Sales Cycle:** 8-12 weeks (partnership evaluation is slow)
- **Deal Size:** $200K-$500K/year (per 50 customers)
- **Win Message:** "Add $200K/year revenue per 50 customers. 70% margin. Zero integration work."

---

## 3. GTM Motion: 3-Phase Launch

### Phase 1: Community & Open-Source Launch (Months 1-3)
**Goal:** 500+ GitHub stars, 50 self-hosted installs, organic awareness

#### Channel 1: GitHub + Product Hunt
- **Timing:** Month 1, Thursday morning (optimal launch window)
- **Execution:**
  - Public GitHub repo (MIT license)
  - Comprehensive README (installation, quick-start, architecture)
  - Open-source license + contribution guidelines
  - Product Hunt launch (target: 3K upvotes, trending #1)
- **Metrics:**
  - 500+ GitHub stars (success threshold: 300+)
  - 50 unique PoC installs (self-reported via GitHub issues)
  - 10 unsolicited feature requests (signals product-market fit)
- **ROI:** $500 in content creation, 20 hours of work → 50 potential customers

#### Channel 2: Hacker News + Reddit
- **Subreddits:** r/netsec, r/devops, r/cybersecurity
- **HN Post:** "ALDECI: open-source unified security platform (ASPM+CTEM+CSPM)"
- **Strategy:** Ask genuine questions ("What's missing?" "How would you improve this?") instead of promotional selling
- **Metrics:**
  - 200+ HN upvotes (success threshold: 100+)
  - 20+ Reddit upvotes per cross-post
  - 5-10 demo requests from security engineers
- **ROI:** 5 hours of work → 10-15 qualified leads

#### Channel 3: Security Blogs & Newsletters
- **Targets:**
  - The Hacker News-adjacent blogs (Lobsters, Lemmy)
  - Security newsletters (Krebs, Dark Reading, Packet Storm)
  - Independent security bloggers (pitch: "free platform to test/review")
- **Metrics:**
  - 2-3 blog posts mentioning ALDECI
  - 1-2 newsletter features (combined reach: 50K+ readers)
  - 30-50 qualified leads from blog traffic
- **ROI:** 10 hours of outreach, 50+ leads

### Phase 1 Success Metrics
- [ ] 500+ GitHub stars
- [ ] 50 self-hosted installs
- [ ] 100+ Twitter followers
- [ ] 50-100 qualified leads (from all channels)
- [ ] 2-3 MSSP pilots (initiated)

---

### Phase 2: MSSP Partnerships (Months 4-6)
**Goal:** 5 MSSP partnerships signed, 200 end customers via MSPs

#### Partnership Strategy
**Why MSSP-first?**
- MSPs have 50-100 customers each (we reach 250 customers through 5 partners)
- MSP sales cycle is faster (8-12 weeks vs. 12-18 months for enterprise)
- MSP white-label = low customer acquisition cost (CAC)
- MSSP economics are so good (70% margin improvement) that partners evangelize

#### Partner Acquisition Motion
1. **Identify Target MSPs** (Month 4)
   - Use ZoomInfo/Apollo to find MSPs with 20-100 customers
   - Filter for those selling Snyk, Lacework, or Rapid7
   - Create list of 50 high-fit MSPs
   - Score by: customer headcount, managed security services revenue, geography (US >80% of initial TAM)

2. **Outreach & Demo** (Month 4-5)
   - Cold email to VP Sales / VP Delivery with specific ROI math:
     ```
     "You have 50 customers. If each spends $2K/year on Snyk + Lacework,
     that's $100K in tool costs. With ALDECI, it's $5K/year total.
     You save your customers $95K and keep 50% of savings = $47.5K new revenue."
     ```
   - 30-minute discovery call (technical evaluation with their engineer)
   - Live demo of white-label dashboard + API
   - Trial license (30 days free for 10-customer pilot)

3. **Pilot & Validation** (Month 5-6)
   - MSSP deploys ALDECI for 10 customers (real production environment)
   - Support calls (we do implementation)
   - Measure: customer feedback, false positive reduction, time-to-value
   - Partner signs 12-month contract (Month 6)

#### Partnership Agreements
- **Standard MSSP License:** $200-500 per customer per year
- **Revenue Share:** MSP keeps 60%, ALDECI keeps 40% (incentivizes sales)
- **Support:** ALDECI provides technical support; MSSP owns customer relationship
- **White-Label:** MSSP's logo on dashboard, white-labeled API docs, branded reports

#### Phase 2 Partner Targets
| Tier | Partner | Customer Count | Estimated ADR | Year 1 Revenue |
|------|---------|---|---|---|
| Tier 1 | Calysto, Nuvemfisc, Onepath Networks | 100 | $250/customer | $25K |
| Tier 1 | Resolute Technology Solutions, Fortified Security | 80 | $250/customer | $20K |
| Tier 2 | 5-10 regional MSPs | 50-100 avg | $200/customer | $60K |
| **Total** | **5 partners** | **~400 customers** | **~$225 avg** | **$105K** |

### Phase 2 Success Metrics
- [ ] 5 MSSP partnerships signed
- [ ] 200+ customer deployments (via MSPs)
- [ ] $105K+ ARR from MSSP channel
- [ ] <20% churn rate (partner satisfaction >8/10)
- [ ] 2-3 MSSP case studies (published)

---

### Phase 3: Direct Enterprise Sales (Months 7-12)
**Goal:** 10 enterprise contracts, $300K/year ACV, $3M ARR by end of year

#### Hiring: Sales Organization
- **Month 7:** Hire VP Sales (focuses on enterprise pipeline)
- **Month 8:** Hire Sales Engineer (technical validation, POC scoping)
- **Month 9:** Hire SDR (outbound prospecting to Fortune 2000 CISOs)
- **Month 11:** Hire AE (enterprise account closing, upsell)

#### Sales Process
1. **Identify Buyer**
   - CISO or VP Engineering at target companies (50-500 employees)
   - Trigger: "recently hired CISO" OR "announced security breach" OR "IPO prep" (compliance)
   - Use ZoomInfo/Apollo + LinkedIn for list of 200 CISOs

2. **Outreach (SDR)**
   - Cold email (personalized, reference recent news) + LinkedIn connection
   - Offer: 20-minute evaluation call (no pitch, just understand their tooling)
   - Goal: 5% reply rate (10 replies out of 200 outreaches)

3. **Qualification (AE/Sales Engineer)**
   - Discovery call (understand: current stack, budget, compliance requirements, timeline)
   - Qualifier: Do they spend $50K+/year on security tools? Do they have data residency requirements?
   - If yes → POC offer

4. **Proof of Concept (Sales Engineer)**
   - 2-week trial (Docker deploy in customer environment)
   - Specific success criteria (e.g., "reduce false positives by 20%," "export SOC2 evidence in <1 hour")
   - Daily check-ins (support + debug)
   - Success = customer ready to buy

5. **Closing (AE)**
   - Negotiation on price ($99-499/month depending on headcount/features)
   - Contract review (15-30 days)
   - Sign + onboard

#### Sales Targets
- **Outreach:** 200 CISOs/VPSec
- **Responses:** 10 replies (5% response rate)
- **Qualified:** 6 opportunities (60% qualification rate)
- **POC:** 4 POCs (67% win rate from qualified)
- **Closed:** 3 deals (75% close rate from POC)
- **Upside:** 5 deals (125% of quota)

#### Enterprise Sales Enablement
- [ ] 30-second elevator pitch (ASPM+CTEM+CSPM, unified, self-hosted, $35-99/month)
- [ ] 2-minute value prop (cost comparison, self-hosted advantage, AI consensus)
- [ ] 15-minute demo (dashboard, alert queue, API, compliance)
- [ ] 30-minute POC scope (customer-specific success criteria)
- [ ] Case studies (3x MSSP case studies + 2x enterprise case studies)
- [ ] Battlecard (vs. Wiz, Lacework, Snyk)
- [ ] ROI calculator (current spend vs. ALDECI savings)

### Phase 3 Success Metrics
- [ ] 10 enterprise contracts signed
- [ ] $300K average contract value (ACL)
- [ ] $3M ARR (10 × $300K)
- [ ] <40% sales cycle (180 days or less)
- [ ] >50% win rate (POC → deal)

---

## 4. Pricing & Packaging

### Freemium Ladder

| Tier | Price | Seats | Assets | Orgs | Connectors | Support | ICP |
|------|-------|-------|--------|------|-----------|---------|-----|
| **Free** | $0 | 5 | 100 | 1 | All (read-only) | Community | Developers, startups |
| **Pro** | $99/mo | 25 | 10K | 10 | All (read+write) | Email (24h) | Mid-market |
| **Enterprise** | $499/mo | Unlimited | Unlimited | Unlimited | Custom + dedicated | Phone (2h) | Enterprise + MSSP |

### Revenue Model
- **Free tier:** Freemium funnel (conversion rate target: 2% → Pro)
- **Pro tier:** Bottom-up sales (CTO/CISO approves $99/month out of departmental budget)
- **Enterprise tier:** Top-down sales (requires CFO approval, SLA negotiation)

### Pricing Strategy
1. **Never charge for core platform** (ASPM+CTEM+CSPM) — keep it free to own the market
2. **Charge for support & compliance** (Pro tier = priority support, Enterprise tier = 24/7 SLA)
3. **Charge for managed hosting** (ALDECI-as-a-Service, Year 2) — avoid on-prem complexity
4. **Charge for custom integrations** (non-standard connectors, e.g., proprietary SOAR)

---

## 5. Marketing Channels & Budget Allocation

### Channel Plan (Year 1, $500K marketing budget)

| Channel | Budget | Allocation | Expected CAC | Expected LTV |
|---------|--------|------------|--------------|--------------|
| **Community (GitHub, HN, Reddit)** | $50K | 10% | $500 (organic) | $3,000 |
| **MSSP Partnerships** | $150K | 30% | $0 (channel revenue-share) | $5,000 |
| **Content Marketing** | $80K | 16% | $1,000 | $4,000 |
| **Paid Ads (LinkedIn, Google)** | $100K | 20% | $2,000 | $4,000 |
| **Events & Sponsorships** | $60K | 12% | $3,000 | $6,000 |
| **PR & Analyst Relations** | $40K | 8% | $2,000 | $8,000 |
| **Sales Enablement** | $20K | 4% | $500 (internal) | $3,000 |

### Channel Breakdown

#### Community (10% budget, organic growth)
- GitHub open-source community
- Hacker News + Reddit + Lobsters
- Twitter/LinkedIn (organic following)
- **Goal:** 500+ stars, 50 self-hosted installs (Month 3)

#### MSSP Partnerships (30% budget, partner-led revenue)
- Outreach, SDR, partner enablement
- White-label implementation support
- Partner event sponsorships
- **Goal:** 5 signed partners, $105K ARR (Month 6)

#### Content Marketing (16% budget, thought leadership)
- Technical blog posts (GraphRAG, AI consensus, self-hosted security)
- YouTube tutorials (10-minute setup guides)
- API documentation + SDK examples
- **Goal:** 1M+ monthly impressions (Month 12)

#### Paid Ads (20% budget, bottom-up lead generation)
- LinkedIn ads to CISOs ("Are you overspending on security tools?")
- Google ads to "security posture management" + "cloud security" keywords
- Reddit + HN sponsored posts
- **Goal:** 500+ qualified leads (Month 12)

#### Events & Sponsorships (12% budget, brand awareness)
- BSides talks (cheaper than RSA, targeted security audience)
- DEF CON talks (hacker community = early adopters)
- InfoSec conferences (SANS, security.dev)
- Sponsor 1-2 security podcasts
- **Goal:** 5+ speaking slots, 100+ qualified leads (Month 12)

#### PR & Analyst Relations (8% budget, credibility)
- Press releases (TechCrunch, The Hacker News)
- Gartner Magic Quadrant submission (qualification process)
- Analyst briefings (Gartner, Forrester, Experian)
- **Goal:** 3+ press mentions, analyst coverage announcement (Month 12)

#### Sales Enablement (4% budget, team productivity)
- CRM software (Salesforce or Pipedrive)
- Sales training + collateral
- Demo environments + POC infrastructure
- **Goal:** 50% reduction in sales cycle time (Month 12)

---

## 6. Customer Acquisition Funnel (Year 1)

```
Top of Funnel (Awareness)
├── GitHub stars: 500
├── HN mentions: 200 upvotes
├── Reddit posts: 100+ upvotes
├── Blog traffic: 10K monthly visitors
├── Paid ads: 5K monthly impressions
└── Total: 50K+ monthly impressions

Middle of Funnel (Consideration)
├── Free tier signups: 500 (from top of funnel)
├── POC requests: 100 (trial → interest)
├── MSSP inquiries: 50 (partnership pipeline)
└── Enterprise trials: 20 (enterprise sales pipeline)

Bottom of Funnel (Decision)
├── Free → Pro conversion: 10 customers ($1.2K/year)
├── MSSP customers: 200 (via 5 partners, $105K ARR)
├── Enterprise deals: 3 (at $300K/year, $900K ARR)
└── Total Year 1 ARR: $1M+
```

---

## 7. Metrics & KPIs (Dashboard)

### Business Metrics
- [ ] **ARR:** Target $775K by Month 12
- [ ] **MRR Growth:** Target 15% MoM
- [ ] **Customer Count:** Target 450 by Month 12
- [ ] **Churn:** Target <5% monthly
- [ ] **Magic Number:** (MRR growth × 12) / Sales & Marketing spend → target 0.75x (healthy for year 1)

### Product Metrics
- [ ] **Free → Pro Conversion:** Target 2% (5 out of 250 signups)
- [ ] **POC Success Rate:** Target 75% (POC → deal)
- [ ] **Time to Value:** Target <15 minutes (deploy) + <1 day (first insight)
- [ ] **Onboarding Completion:** Target 80% complete setup in first week

### Sales Metrics
- [ ] **Sales Cycle:** Target <90 days (from first call to deal close)
- [ ] **Win Rate:** Target 50% (qualified opportunities → customers)
- [ ] **CAC:** Target <$1,000 for Pro, <$5,000 for Enterprise
- [ ] **LTV:CAC Ratio:** Target >3x (healthy unit economics)

### Marketing Metrics
- [ ] **GitHub Stars:** 500+ (Month 3)
- [ ] **Monthly Website Traffic:** 10K+ unique visitors (Month 12)
- [ ] **Email Subscriber Growth:** 5K+ (Month 12)
- [ ] **Social Following:** 5K+ on LinkedIn, 2K+ on Twitter (Month 12)

---

## 8. 6-Month Milestone

By Month 6 (September 2026), we should have achieved:

| Metric | Target | Status |
|--------|--------|--------|
| **ARR** | $105K (MSSP channel) | On track if 5 partners signed |
| **Customers** | 200+ (via 5 MSSP partners) | On track if MSSP partnerships execute |
| **GitHub Stars** | 500+ | On track if community launch successful |
| **MSSP Partners** | 5 signed | Critical path |
| **Enterprise Pilots** | 3-5 in progress | Hire VP Sales by Month 7 |
| **Employees** | 6-8 (founders + 2-3 hires) | On track |
| **Burn Rate** | $50K/month (runway: 18 months on $2M seed) | On track |

If we miss these milestones by Month 6:
- **Pivot:** Accelerate free-tier conversion (2% → 5% by Month 12)
- **Pivot:** Focus on single MSSP (depth over breadth) instead of 5 partners
- **Pivot:** Productize compliance packs (HIPAA, PCI) as paid add-ons

---

## 9. Key Dependencies & Risks

### Critical Path (Must-Haves)
1. **GitHub stars + community buzz** (Month 1-3): If <100 stars, we have low product-market fit; restart messaging
2. **MSSP partner signed** (Month 4-6): If zero partners, enterprise sales is only path; expensive and slow
3. **First paying customer** (Month 2): If we can't convert a single customer in first 90 days, model breaks

### Risks & Mitigations
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| Community ignores ALDECI (GitHub launch flops) | 20% | HIGH | Have backup: cold email to CISOs, start MSSP early |
| MSSP partners won't white-label (API concerns) | 10% | HIGH | Pre-build white-label dashboard, simplify API surface |
| Enterprise sales takes 18+ months | 40% | MEDIUM | Lean on MSSP channel, don't hire enterprise sales until Month 9 |
| Competitors (Wiz, Snyk) copy our model | 70% | MEDIUM | Move fast on MSSP partnerships (lock in 5 before Q3 2026) |
| Budget runs out before profitability | 30% | HIGH | Raise Series A in Month 12-15, extend runway with MSSP revenue |

---

## 10. Sales Playbooks

### Playbook 1: Free → Pro Conversion
**Motion:** Self-serve freemium funnel

1. **Free Signup** (Day 0)
   - User deploys ALDECI via `docker compose up`
   - First alert appears within 5 minutes
   - Email: "Welcome to ALDECI. Here's your first insight. 👋"

2. **Aha Moment** (Day 1-3)
   - User connects GitHub/AWS and sees 10 vulnerabilities
   - Email: "You have 10 vulnerabilities. Prioritize by risk. [Learn more]"
   - In-app: "Upgrade to Pro for compliance reports, Slack alerts, API access"

3. **Pain Point** (Day 7)
   - Free tier users hit 100-asset limit
   - Email: "You've hit the free tier limit. Upgrade to Pro for 10K assets. $99/month."
   - In-app: "Upgrade now to continue"

4. **Conversion** (Day 14-30)
   - 2% of free users convert to Pro
   - Typical profile: Security engineer at 100-employee startup
   - Deal size: $99/month = $1,188/year

**Success Metrics:**
- Free signups: 500 (Month 3)
- Pro conversions: 10 (Month 6)
- Conversion rate: 2%
- LTV: $3,000 (assuming 30-month retention)

---

### Playbook 2: MSSP White-Label
**Motion:** Partner-driven enterprise sales

1. **Outreach** (Week 1)
   - Cold email to MSSP VP Sales with ROI math
   - Subject: "[COMPANY]: Cut customer tool costs by 95%. Add $47.5K revenue."

2. **Discovery Call** (Week 2)
   - 30-minute call with VP Sales + their Security Lead
   - Show: dashboard mockup, API docs, customer list, pricing
   - Ask: "How many customers? What tools do they use? Budget per customer?"

3. **Technical Evaluation** (Week 3-4)
   - Deploy ALDECI in MSSP test environment
   - MSSP's engineer integrates with their customer data (AWS, GitHub, etc.)
   - Success metric: "Can you generate a compliance report for a customer in <30 minutes?"

4. **Pilot** (Week 5-6)
   - MSSP white-labels ALDECI for 10 customers (production)
   - We provide implementation support + training
   - Success metric: "10 customers see 30% false positive reduction, deploy in <1 week"

5. **Contract** (Week 7-8)
   - MSSP signs 12-month agreement
   - Price: $250/customer/year (MSSP pays, keeps 60%, gives 40% to ALDECI)
   - SLA: We provide technical support, MSSP owns customer relationship

6. **Scale** (Month 2+)
   - MSSP enrolls additional customers (target: 50 per partner)
   - Recurring revenue: $250 × 50 = $12.5K/year per MSSP

**Success Metrics:**
- Outreach: 50 MSPs
- Qualified: 10 (20% qualification)
- Pilots: 5 (50% pilot conversion)
- Signed: 5 (100% pilot-to-contract)
- Customers: 250 (50 customers × 5 partners)
- Annual revenue: $62.5K (250 customers × $250/year × 40% share)

---

### Playbook 3: Enterprise Bottom-Up (CTO/CISO)
**Motion:** Problem-aware direct sales

1. **Prospecting** (Week 1)
   - Identify CISO/VP Engineering at target company
   - Research: "What tools do they use? Recent news? Security incident?"
   - Personalized cold email: "I noticed you're using Wiz + Snyk + Rapid7. We built a unified platform."

2. **Discovery Call** (Week 2)
   - 20-minute conversation (no pitch)
   - Questions: "What's working? What's painful? How much do you spend?"
   - Goal: Qualify if they're a fit (spending $50K+/year on tools?)

3. **Qualification** (Week 3)
   - If yes → "Want to run a 2-week trial?"
   - If no → "Call me back if your situation changes."

4. **POC Proposal** (Week 4)
   - Email with specifics: "We'll deploy ALDECI in your AWS account. Success criteria: export SOC2 evidence in <1 hour, reduce Snyk false positives by 20%."
   - Requires executive sign-off (CISO approval)

5. **Proof of Concept** (Week 5-6)
   - We deploy in customer's environment (EC2 instance, RDS, everything)
   - Daily standups (our Sales Engineer + customer's Security Lead)
   - Measure: Alert accuracy, compliance report generation, time-to-deploy

6. **Deal Negotiation** (Week 7-8)
   - If POC succeeds: "Ready to buy?"
   - Pricing: $99-499/month depending on headcount + compliance requirements
   - Contract: 12 months, with renewal option

7. **Closing** (Week 9-10)
   - Legal review (15-30 days in enterprise)
   - Sign + onboard

**Success Metrics:**
- Outreach: 200 CISOs
- Responses: 10 (5% reply rate)
- Qualified: 6 (60% qualification)
- POCs: 4 (67% POC rate)
- Closed: 3 (75% close rate)
- Deal size: $300K/year average (assuming $499/month × 50-employee companies × 12 months)
- Annual revenue: $900K

---

## 11. Conclusion

ALDECI's GTM strategy is **community-first, MSSP-led, enterprise-optimized**:

1. **Months 1-3:** Launch on GitHub, get stars, recruit early adopters (MSSP partners, CISOs)
2. **Months 4-6:** Lock in 5 MSSP partnerships, reach 200 customers via partners ($105K ARR)
3. **Months 7-12:** Hire enterprise sales team, close 3-5 enterprise deals ($900K ARR)
4. **Year 1 Total:** $1M+ ARR, 450+ customers, 500+ GitHub stars, Series A-ready

**Key Assumption:** MSSP partnerships are the fastest path to $1M ARR. Community growth is the moat. Enterprise deals are the long-term play.

**Pivot Points:** If MSSP partnerships don't materialize by Month 6, accelerate free-tier conversion + focus on SMB bottom-up motion. If enterprise deals don't close by Month 9, we pivot to MSSP-only and raise a smaller Series A.

---

*Last updated: 2026-04-16 | ALDECI v2.5*
