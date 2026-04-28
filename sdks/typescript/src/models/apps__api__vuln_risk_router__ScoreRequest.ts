/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { VulnContext } from './VulnContext';
export type apps__api__vuln_risk_router__ScoreRequest = {
    /**
     * CVE identifier, e.g. CVE-2024-12345
     */
    cve_id: string;
    /**
     * Organization identifier
     */
    org_id: string;
    context?: VulnContext;
    /**
     * Optional asset to attach score to
     */
    asset_id?: (string | null);
    /**
     * Persist score to DB for trending
     */
    save?: boolean;
};

