/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Campaign } from './Campaign';
import type { ThreatActor } from './ThreatActor';
/**
 * Result of correlating a finding against threat intelligence.
 *
 * Attributes:
 * finding_id: The finding being correlated
 * threat_actor: Matched threat actor (None if no match)
 * campaign: Matched campaign (None if no match)
 * confidence: Confidence score 0.0–1.0
 * ioc_matches: IOCs from the finding that matched the actor/campaign
 * ttp_matches: TTPs from the finding that matched the actor/campaign
 */
export type ThreatCorrelation = {
    finding_id: string;
    threat_actor?: (ThreatActor | null);
    campaign?: (Campaign | null);
    confidence?: number;
    ioc_matches?: Array<string>;
    ttp_matches?: Array<string>;
};

