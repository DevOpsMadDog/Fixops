/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReachabilityLevel } from './ReachabilityLevel';
import type { RemediationRecommendation } from './RemediationRecommendation';
import type { RiskBucket } from './RiskBucket';
/**
 * A vulnerability with full composite priority score.
 */
export type PrioritizedVuln = {
    id?: string;
    finding_id: string;
    cve_id?: (string | null);
    title: string;
    asset_id: string;
    asset_name: string;
    epss_score?: number;
    reachability?: ReachabilityLevel;
    reachability_factor?: number;
    business_impact?: number;
    compensating_controls?: number;
    composite_score?: number;
    risk_bucket?: RiskBucket;
    sla_deadline?: (string | null);
    sla_breached?: boolean;
    days_open?: number;
    assigned_team?: (string | null);
    group_id?: (string | null);
    recommendations?: Array<RemediationRecommendation>;
    discovered_at?: string;
    last_prioritized?: string;
    org_id?: string;
};

