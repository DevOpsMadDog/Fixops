/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { VulnSeverity } from './VulnSeverity';
import type { VulnStatus } from './VulnStatus';
/**
 * Response for discovered vulnerability.
 */
export type DiscoveredVulnResponse = {
    id: string;
    internal_id: string;
    title: string;
    severity: VulnSeverity;
    status: VulnStatus;
    created_at: string;
    discovered_by: string;
    cvss_score?: (number | null);
    cve_id?: (string | null);
};

