#!/usr/bin/env python3
"""Replace Math.random() in MPTEConsole.tsx with deterministic seeded values."""

filepath = "suite-ui/aldeci/src/pages/attack/MPTEConsole.tsx"

with open(filepath, "r") as f:
    content = f.read()

# 1. Add seeded PRNG after EASE_OUT_EXPO
old_after_ease = """const EASE_OUT_EXPO: [number, number, number, number] = [0.16, 1, 0.3, 1];

// ─────────────────────────────────────────────────────────────────────────────
// Demo Data Generator
// ─────────────────────────────────────────────────────────────────────────────"""

new_after_ease = """const EASE_OUT_EXPO: [number, number, number, number] = [0.16, 1, 0.3, 1];

// Deterministic seeded PRNG — produces stable demo data across renders
// Uses a simple mulberry32 algorithm seeded by phase/target index
function seededRandom(seed: number): number {
  let t = (seed + 0x6D2B79F5) | 0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

// Pre-computed deterministic durations per phase (ms) — avoids any randomness
const DEMO_PHASE_DURATIONS = [
  1240, 1830, 2150, 980, 1560, 2340, 1890, 760, 1120, 2480,
  1670, 2010, 1340, 1780, 2200, 950, 1430, 1680, 1950
];

// Pre-computed deterministic confidence contributions per phase
const DEMO_PHASE_CONFIDENCE = [5, 7, 4, 8, 6, 5, 9, 3, 7, 6, 8, 5, 4, 7, 6, 3, 5, 8, 7];

// ─────────────────────────────────────────────────────────────────────────────
// Demo Data Generator (deterministic — no Math.random())
// ─────────────────────────────────────────────────────────────────────────────"""

content = content.replace(old_after_ease, new_after_ease, 1)

# 2. Replace generateDemoPhases with deterministic version
old_generate_phases = """function generateDemoPhases(verdict: Verdict, scope: VerificationScope): PhaseResult[] {
  const maxPhase = scope === 'quick' ? 6 : scope === 'standard' ? 12 : 19;
  const isExploitable = verdict === 'EXPLOITABLE';
  const failPoint = isExploitable ? -1 : Math.floor(Math.random() * 6) + 7;

  return MPTE_PHASES.map((phase) => {
    if (phase.id > maxPhase) {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 0,
        evidence: 'Phase skipped - outside scan scope',
        details: `Not included in ${scope} scope verification`,
        confidenceContribution: 0, relatedPhases: [],
      };
    }
    if (phase.id === failPoint) {
      return {
        phaseId: phase.id, status: 'FAIL' as PhaseStatus,
        durationMs: Math.random() * 5000 + 500,
        evidence: generateEvidence(phase.id, 'FAIL'),
        details: `${phase.name} failed - vulnerability not exploitable at this stage`,
        confidenceContribution: -15,
        relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
      };
    }
    if (phase.id > failPoint && failPoint > 0) {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 0,
        evidence: 'Phase skipped due to prior phase failure',
        details: `Skipped because Phase ${failPoint} failed`,
        confidenceContribution: 0, relatedPhases: [failPoint],
      };
    }
    if (phase.id === 9 && Math.random() > 0.5) {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 100,
        evidence: 'Pre-auth vectors not applicable - target requires authentication',
        details: 'Target enforces authentication on all endpoints',
        confidenceContribution: 0, relatedPhases: [10],
      };
    }
    return {
      phaseId: phase.id, status: 'PASS' as PhaseStatus,
      durationMs: Math.random() * 4000 + 200,
      evidence: generateEvidence(phase.id, 'PASS'),
      details: `${phase.name} completed successfully`,
      confidenceContribution: Math.floor(Math.random() * 10) + 3,
      relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
    };
  });
}"""

new_generate_phases = """function generateDemoPhases(verdict: Verdict, scope: VerificationScope): PhaseResult[] {
  const maxPhase = scope === 'quick' ? 6 : scope === 'standard' ? 12 : 19;
  const isExploitable = verdict === 'EXPLOITABLE';
  // Deterministic fail point based on verdict: NOT_EXPLOITABLE fails at phase 10, INCONCLUSIVE at phase 8
  const failPoint = isExploitable ? -1 : verdict === 'NOT_EXPLOITABLE' ? 10 : 8;

  return MPTE_PHASES.map((phase) => {
    if (phase.id > maxPhase) {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 0,
        evidence: 'Phase skipped - outside scan scope',
        details: `Not included in ${scope} scope verification`,
        confidenceContribution: 0, relatedPhases: [],
      };
    }
    if (phase.id === failPoint) {
      return {
        phaseId: phase.id, status: 'FAIL' as PhaseStatus,
        durationMs: DEMO_PHASE_DURATIONS[phase.id - 1] + 500,
        evidence: generateEvidence(phase.id, 'FAIL'),
        details: `${phase.name} failed - vulnerability not exploitable at this stage`,
        confidenceContribution: -15,
        relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
      };
    }
    if (phase.id > failPoint && failPoint > 0) {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 0,
        evidence: 'Phase skipped due to prior phase failure',
        details: `Skipped because Phase ${failPoint} failed`,
        confidenceContribution: 0, relatedPhases: [failPoint],
      };
    }
    if (phase.id === 9 && verdict === 'NOT_EXPLOITABLE') {
      return {
        phaseId: phase.id, status: 'SKIP' as PhaseStatus, durationMs: 100,
        evidence: 'Pre-auth vectors not applicable - target requires authentication',
        details: 'Target enforces authentication on all endpoints',
        confidenceContribution: 0, relatedPhases: [10],
      };
    }
    return {
      phaseId: phase.id, status: 'PASS' as PhaseStatus,
      durationMs: DEMO_PHASE_DURATIONS[phase.id - 1],
      evidence: generateEvidence(phase.id, 'PASS'),
      details: `${phase.name} completed successfully`,
      confidenceContribution: DEMO_PHASE_CONFIDENCE[phase.id - 1],
      relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
    };
  });
}"""

content = content.replace(old_generate_phases, new_generate_phases, 1)

# 3. Fix report ID in generateEvidence
content = content.replace(
    "Report ID: RPT-2026-${Math.random().toString(36).slice(2, 8).toUpperCase()}`",
    "Report ID: RPT-2026-A7K3F9`",
    1
)

# 4. Replace generateDemoVerifications with deterministic version
old_generate_verifications = """function generateDemoVerifications(): VerificationResult[] {
  const targets = [
    { target: 'api.acmecorp.com', url: 'https://api.acmecorp.com', cve: 'CVE-2024-38816' },
    { target: 'staging.payments.io', url: 'https://staging.payments.io:8443', cve: 'CVE-2024-21626' },
    { target: '10.0.1.45 (Jenkins)', url: 'http://10.0.1.45:8080', cve: 'CVE-2024-23897' },
    { target: 'auth.internal.dev', url: 'https://auth.internal.dev', cve: null },
    { target: 'k8s-api.prod.cluster', url: 'https://k8s-api.prod.cluster:6443', cve: 'CVE-2024-21626' },
    { target: 'graphql.app.io', url: 'https://graphql.app.io/graphql', cve: 'CVE-2023-44487' },
  ];
  const verdicts: Verdict[] = ['EXPLOITABLE', 'EXPLOITABLE', 'NOT_EXPLOITABLE', 'INCONCLUSIVE', 'EXPLOITABLE', 'NOT_EXPLOITABLE'];
  const scopes: VerificationScope[] = ['full', 'full', 'standard', 'quick', 'full', 'standard'];

  return targets.map((t, i) => ({
    id: `vr-${(1000 + i).toString(36)}-${Date.now().toString(36)}`,
    requestId: `req-${(2000 + i).toString(36)}`,
    target: t.target,
    targetUrl: t.url,
    cveId: t.cve,
    verdict: verdicts[i],
    confidenceScore: verdicts[i] === 'EXPLOITABLE' ? 85 + Math.floor(Math.random() * 15)
      : verdicts[i] === 'NOT_EXPLOITABLE' ? 70 + Math.floor(Math.random() * 20)
      : 40 + Math.floor(Math.random() * 30),
    scope: scopes[i],
    phases: generateDemoPhases(verdicts[i], scopes[i]),
    startedAt: new Date(Date.now() - Math.random() * 86400000 * 3).toISOString(),
    completedAt: verdicts[i] === 'IN_PROGRESS' ? null : new Date(Date.now() - Math.random() * 86400000).toISOString(),
    riskScore: verdicts[i] === 'EXPLOITABLE' ? 7.5 + Math.random() * 2.5 : verdicts[i] === 'NOT_EXPLOITABLE' ? 1 + Math.random() * 3 : 4 + Math.random() * 3,
    findingId: `FND-${(3000 + i).toString()}`,
    failScore: verdicts[i] === 'EXPLOITABLE'
      ? { grade: 'F', score: 85 + Math.floor(Math.random() * 15) }
      : verdicts[i] === 'NOT_EXPLOITABLE'
      ? { grade: 'A', score: 10 + Math.floor(Math.random() * 20) }
      : { grade: 'C', score: 40 + Math.floor(Math.random() * 20) },
  }));
}"""

new_generate_verifications = """function generateDemoVerifications(): VerificationResult[] {
  const targets = [
    { target: 'api.acmecorp.com', url: 'https://api.acmecorp.com', cve: 'CVE-2024-38816' },
    { target: 'staging.payments.io', url: 'https://staging.payments.io:8443', cve: 'CVE-2024-21626' },
    { target: '10.0.1.45 (Jenkins)', url: 'http://10.0.1.45:8080', cve: 'CVE-2024-23897' },
    { target: 'auth.internal.dev', url: 'https://auth.internal.dev', cve: null },
    { target: 'k8s-api.prod.cluster', url: 'https://k8s-api.prod.cluster:6443', cve: 'CVE-2024-21626' },
    { target: 'graphql.app.io', url: 'https://graphql.app.io/graphql', cve: 'CVE-2023-44487' },
  ];
  const verdicts: Verdict[] = ['EXPLOITABLE', 'EXPLOITABLE', 'NOT_EXPLOITABLE', 'INCONCLUSIVE', 'EXPLOITABLE', 'NOT_EXPLOITABLE'];
  const scopes: VerificationScope[] = ['full', 'full', 'standard', 'quick', 'full', 'standard'];

  // Deterministic confidence scores per verdict type
  const confidenceScores = [92, 88, 78, 55, 95, 82];
  // Deterministic risk scores per target
  const riskScores = [9.2, 8.7, 2.1, 5.8, 9.5, 1.8];
  // Deterministic FAIL scores per target
  const failScores: { grade: string; score: number }[] = [
    { grade: 'F', score: 92 },
    { grade: 'F', score: 88 },
    { grade: 'A', score: 18 },
    { grade: 'C', score: 55 },
    { grade: 'F', score: 95 },
    { grade: 'A', score: 15 },
  ];
  // Deterministic timestamps — offsets in hours from a reference point
  const startOffsets = [72, 48, 36, 24, 12, 6]; // hours ago
  const completeOffsets = [70, 46, 34, 22, 10, 4]; // hours ago

  const now = Date.now();
  return targets.map((t, i) => ({
    id: `vr-${(1000 + i).toString(36)}-demo`,
    requestId: `req-${(2000 + i).toString(36)}`,
    target: t.target,
    targetUrl: t.url,
    cveId: t.cve,
    verdict: verdicts[i],
    confidenceScore: confidenceScores[i],
    scope: scopes[i],
    phases: generateDemoPhases(verdicts[i], scopes[i]),
    startedAt: new Date(now - startOffsets[i] * 3600000).toISOString(),
    completedAt: verdicts[i] === 'IN_PROGRESS' ? null : new Date(now - completeOffsets[i] * 3600000).toISOString(),
    riskScore: riskScores[i],
    findingId: `FND-${(3000 + i).toString()}`,
    failScore: failScores[i],
  }));
}"""

content = content.replace(old_generate_verifications, new_generate_verifications, 1)

# 5. Replace LiveRunViewer Math.random() for phase duration and outcome simulation
# Replace the phase simulation section with deterministic values based on phase index
old_live_sim = """    // Simulate this phase running for 800-3000ms
    const duration = Math.random() * 2200 + 800;

    phaseTimerRef.current = setTimeout(() => {
      // Decide outcome — 80% pass, 10% fail, 10% skip
      const roll = Math.random();
      let status: PhaseStatus;
      if (roll < 0.1 && currentPhaseIdx >= 6) {
        status = 'FAIL';
      } else if (roll < 0.15 && currentPhaseIdx >= 5) {
        status = 'SKIP';
      } else {
        status = 'PASS';
      }

      const result: PhaseResult = {
        phaseId: phaseDef.id,
        status,
        durationMs: duration,
        evidence: generateEvidence(phaseDef.id, status),
        details: `${phaseDef.name} ${status === 'PASS' ? 'completed successfully' : status === 'FAIL' ? 'failed' : 'skipped'}`,
        confidenceContribution: status === 'PASS' ? Math.floor(Math.random() * 8) + 3 : status === 'FAIL' ? -15 : 0,
        relatedPhases: [phaseDef.id - 1, phaseDef.id + 1].filter(p => p > 0 && p <= 19),
      };"""

new_live_sim = """    // Deterministic phase duration based on phase index
    const duration = DEMO_PHASE_DURATIONS[currentPhaseIdx] || 1500;

    phaseTimerRef.current = setTimeout(() => {
      // Deterministic outcome based on phase index using seeded PRNG
      const seed = currentPhaseIdx * 7 + 42;
      const roll = seededRandom(seed);
      let status: PhaseStatus;
      if (roll < 0.1 && currentPhaseIdx >= 6) {
        status = 'FAIL';
      } else if (roll < 0.15 && currentPhaseIdx >= 5) {
        status = 'SKIP';
      } else {
        status = 'PASS';
      }

      const result: PhaseResult = {
        phaseId: phaseDef.id,
        status,
        durationMs: duration,
        evidence: generateEvidence(phaseDef.id, status),
        details: `${phaseDef.name} ${status === 'PASS' ? 'completed successfully' : status === 'FAIL' ? 'failed' : 'skipped'}`,
        confidenceContribution: status === 'PASS' ? DEMO_PHASE_CONFIDENCE[currentPhaseIdx] : status === 'FAIL' ? -15 : 0,
        relatedPhases: [phaseDef.id - 1, phaseDef.id + 1].filter(p => p > 0 && p <= 19),
      };"""

content = content.replace(old_live_sim, new_live_sim, 1)

with open(filepath, "w") as f:
    f.write(content)

# Verify no Math.random() remains (except in the seededRandom comment)
remaining = [line for i, line in enumerate(content.split('\n'), 1)
             if 'Math.random()' in line]
if remaining:
    print(f"WARNING: {len(remaining)} Math.random() still in file:")
    for line in remaining:
        print(f"  {line.strip()}")
else:
    print("SUCCESS: All Math.random() removed from MPTEConsole.tsx")

print(f"\nFile size: {len(content)} bytes, {len(content.split(chr(10)))} lines")
