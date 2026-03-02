# ALdeci — Go-To-Market Plan

**Version**: 3.0 | **Date**: 2026-03-02 | **Owner**: VP Marketing
**Pillars**: [V3] Decision Intelligence, [V5] MPTE, [V7] MCP-Native

---

## Target Personas

### Primary Decision Makers
| Persona | Title | Pain Point | ALdeci Value |
|---------|-------|-----------|-------------|
| **CISO** | Chief Information Security Officer | Tool sprawl, alert fatigue, board reporting, compliance | Single pane of glass, verified risk posture, audit-ready evidence |
| **VP Engineering** | VP/SVP Engineering | Dev velocity blocked by security debt, false positive waste | 97% noise reduction, AutoFix PRs, developer-friendly triage |
| **DevSecOps Lead** | Director/Sr. Manager DevSecOps | Manual triage across 10+ tools, no prioritization | Brain Pipeline auto-triage, scanner-neutral orchestration |

### Key Influencers
| Persona | Title | Pain Point | ALdeci Value |
|---------|-------|-----------|-------------|
| **AppSec Engineer** | Sr. Application Security Engineer | Daily triage of thousands of findings | Multi-AI consensus reduces workload 90%+ |
| **Compliance Lead** | Director of Compliance/GRC | Manual evidence collection, audit prep | Quantum-secure evidence bundles, auto-generated |
| **CTO** | Chief Technology Officer | Architecture consolidation, AI strategy | MCP-native platform, air-gapped deployment |

---

## Ideal Customer Profile (ICP)

### Firmographic
- **Company size**: 200-2,000 developers (mid-market to enterprise)
- **Industry**: Financial services, healthcare, government/defense, SaaS/technology
- **Security maturity**: Running 5+ security scanners, dedicated AppSec team of 3+ people
- **Pain signal**: Complaining about alert fatigue, false positive rates, or audit prep effort
- **Budget**: $100K-$300K annual security tooling budget

### Behavioral Signals
- Recently purchased or evaluated an ASPM solution (ArmorCode, Apiiro, etc.)
- Talking about "CTEM" or "exposure management" in job postings or conference talks
- Hiring for DevSecOps or AppSec automation roles
- Running air-gapped or hybrid environments (defense, critical infrastructure)
- Planning SOC2/PCI-DSS/HIPAA compliance audit in next 6 months

### Disqualification Signals
- <50 developers (too small for enterprise tooling)
- Single-scanner environment (insufficient pain for orchestration)
- No security team (need product-led growth, not enterprise sales)
- Already deep in Google Cloud Platform (Wiz post-acquisition may suffice)

---

## Pricing Strategy

### Model: Per-Application, Tiered

| Tier | Price | Apps | Features | Target |
|------|-------|------|----------|--------|
| **Community** | Free | Up to 3 | Brain Pipeline (4 steps) + 2 native scanners | OSS teams, individuals |
| **Professional** | $3-5K/mo | Up to 25 | Full pipeline + all scanners + basic AutoFix | Mid-market, 50-200 devs |
| **Enterprise** | $8-15K/mo | Unlimited | Multi-LLM + MPTE + compliance evidence + integrations | Large orgs, 200-2,000 devs |
| **Air-Gapped** | $15-25K/mo | Unlimited | Full platform + self-hosted AI + quantum crypto + on-prem | Gov/Defense/Financial |

### Pricing Rationale
- **Per-app, not per-developer**: Aligns with DevSecOps teams (one team manages many apps)
- **Community tier is real**: Brain Pipeline dedup + 2 scanners = genuine value. Drives adoption.
- **Air-gapped premium**: Defense/financial customers expect and accept 2-3x pricing for on-prem
- **Expansion motion**: Customers start with 5 apps, expand to 50+ as value proves out (target 130% NRR)

---

## Channel Strategy

### Phase 1: Founder-Led Sales (Now - Q3 2026)
- CEO demos to design partners directly
- 5-10 design partner deployments (free, with integration support)
- Focus on Financial Services and Healthcare (highest pain, regulated)
- Conference presence: RSA 2026 (May), BlackHat 2026 (August)

### Phase 2: Inbound + PLG (Q3 2026 - Q1 2027)
- Community tier drives inbound leads (product-led growth)
- Blog content + thought leadership (multi-AI consensus, CTEM+, exploit verification)
- GitHub open-source engagement (scanner parsers, MCP tools)
- Developer relations: DevSecOps meetups, podcasts, webinars

### Phase 3: Channel + Partners (Q1 2027+)
- Technology partnerships: Scanner vendors (Snyk, Semgrep, Trivy — we make them better)
- SI partnerships: Deloitte, Accenture (compliance-focused implementations)
- Managed security: MSSPs deploying ALdeci for their clients
- Cloud marketplace: AWS Marketplace, Azure Marketplace listings

---

## Launch Sequence (Enterprise Demo Sprint Focus)

### Week 1 (Mar 1-6): Enterprise Demo
- [x] Demo talking points one-pager v3.0 (9 differentiators + Claude Code Security angle)
- [x] Competitive battlecards (6 competitors — all updated with Claude Code Security intel, verified LOC)
- [x] Positioning document v3.0 (Claude Code Security messaging + verified LOC)
- [x] Investor narrative v3.0 (updated numbers + Claude Code Security market context)
- [x] Blog: "Claude finds. ALdeci decides." (NEW — time-sensitive response to Anthropic launch)
- [x] LinkedIn: "500 More Zero-Days. Now What?" (NEW — Claude Code Security hook for LinkedIn)
- [x] 5 persona walkthrough scripts (sales-engineer: DONE 2026-03-01)
- [ ] Post-demo follow-up email template
- [ ] Demo video script (5-minute version)

### Week 2 (Mar 7-13): Content Blitz
- [ ] Blog: "Why Multi-AI Consensus Beats Single-Model Security" (done, publish)
- [ ] LinkedIn post: "The 11,300 Finding Problem" (done, publish)
- [ ] Blog: "CTEM+ vs. ASPM: Why Gartner's Framework Isn't Enough"
- [ ] LinkedIn post: "Wiz Goes to Google — What It Means for Security Neutrality"
- [ ] Twitter/X thread: "19 Phases of MPTE"

### Week 3 (Mar 14-20): Investor Outreach
- [ ] Investor one-pager (1 page, PDF)
- [ ] Email template: Pre-seed investor outreach
- [ ] Pitch deck (10 slides, Figma)
- [ ] Design partner case study template

### Week 4+ (Mar 21+): Sustained GTM
- [ ] Website copy update (positioning refresh)
- [ ] Press release draft (company launch)
- [ ] Analyst briefing template (Gartner, Forrester)
- [ ] RSA 2026 submission (if deadline allows)

---

## Metrics to Track

### Leading Indicators
| Metric | Target (6 months) | Owner |
|--------|-------------------|-------|
| Design partner deployments | 5-10 | CEO + Sales |
| Demo requests (inbound) | 50+ | Marketing |
| Content engagement (views/shares) | 10K+ monthly | Marketing |
| Community tier signups | 500+ | Product/Marketing |
| GitHub stars / contributions | 1K+ | DevRel |

### Lagging Indicators
| Metric | Target (12 months) | Owner |
|--------|-------------------|-------|
| Pipeline value | $2M+ | Sales |
| ACV | $60-180K | Sales |
| Paying customers | 20+ | Sales |
| ARR | $2M+ | CEO |
| NRR | 130%+ | Customer Success |

---

## Key Messages by Channel

### Enterprise Demo
> "ALdeci turns 10,000 security findings into 10 actionable decisions — verified, not guessed — and fixes them before your next standup."

### Investor Pitch
> "We're building the decision intelligence layer for the $28.5B application security market. Multi-AI consensus makes every scanner intelligent. First complete CTEM+ platform."

### Developer Community
> "Stop triaging. Start shipping. ALdeci's Brain Pipeline turns your scanner noise into actionable, verified, auto-fixed security cases."

### Compliance Audience
> "Quantum-secure evidence bundles. Auto-generated. Machine-verifiable. SOC2, PCI-DSS, HIPAA — on autopilot."

### CISO/Board
> "One platform for your entire application security posture. Scanner-neutral, air-gapped capable, AI-powered decisions with cryptographic proof."

---

*Updated 2026-03-01 based on AI Researcher market intelligence and competitive analysis.*
