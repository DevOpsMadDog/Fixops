/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__connector_routes__FindingSeverity } from './apps__api__connector_routes__FindingSeverity';
import type { core__analytics_models__FindingStatus } from './core__analytics_models__FindingStatus';
/**
 * Request model for creating a finding.
 */
export type apps__api__analytics_router__FindingCreate = {
    /**
     * Organization ID for multi-tenancy
     */
    org_id: string;
    application_id?: (string | null);
    service_id?: (string | null);
    rule_id: string;
    severity: apps__api__connector_routes__FindingSeverity;
    status?: core__analytics_models__FindingStatus;
    title: string;
    description: string;
    source: string;
    cve_id?: (string | null);
    cvss_score?: (number | null);
    epss_score?: (number | null);
    exploitable?: boolean;
    metadata?: Record<string, any>;
};

