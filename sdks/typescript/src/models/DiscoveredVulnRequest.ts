/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AffectedComponent } from './AffectedComponent';
import type { AttackVector } from './AttackVector';
import type { DiscoverySource } from './DiscoverySource';
import type { ImpactType } from './ImpactType';
import type { VulnerabilityEvidence } from './VulnerabilityEvidence';
import type { VulnSeverity } from './VulnSeverity';
/**
 * Request to report a discovered vulnerability.
 *
 * Most fields are optional with sensible defaults to support both quick
 * reporting from the UI and detailed researcher submissions.
 */
export type DiscoveredVulnRequest = {
    title?: string;
    description?: string;
    severity?: VulnSeverity;
    impact_type?: ImpactType;
    attack_vector?: AttackVector;
    discovery_source?: DiscoverySource;
    /**
     * Researcher/team name
     */
    discovered_by?: string;
    discovered_date?: (string | null);
    affected_components?: Array<AffectedComponent>;
    /**
     * e.g., '< 2.1.5' or '1.0.0 - 2.0.0'
     */
    affected_versions?: string;
    /**
     * PoC code or steps
     */
    proof_of_concept?: (string | null);
    /**
     * trivial, low, medium, high
     */
    exploitation_difficulty?: string;
    /**
     * CVSS 3.1 vector string
     */
    cvss_vector?: (string | null);
    cvss_score?: (number | null);
    remediation?: (string | null);
    workaround?: (string | null);
    evidence?: Array<VulnerabilityEvidence>;
    /**
     * Keep internal, don't publish
     */
    internal_only?: boolean;
    notify_vendor?: boolean;
    references?: Array<string>;
    tags?: Array<string>;
};

