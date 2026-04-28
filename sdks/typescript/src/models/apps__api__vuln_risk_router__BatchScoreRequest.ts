/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BatchVulnItem } from './BatchVulnItem';
export type apps__api__vuln_risk_router__BatchScoreRequest = {
    vulnerabilities: Array<BatchVulnItem>;
    org_id: string;
    /**
     * Persist all scores to DB
     */
    save?: boolean;
};

