/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to assign an SLA to a finding.
 */
export type AssignSLARequest = {
    finding_id: string;
    /**
     * critical | high | medium | low
     */
    severity: string;
    /**
     * Discovery timestamp (UTC); defaults to now
     */
    discovered_at?: (string | null);
    team_id?: (string | null);
    /**
     * tier1–tier5
     */
    asset_tier?: string;
    /**
     * Active compliance frameworks (e.g. pci-dss, hipaa)
     */
    frameworks?: Array<string>;
};

