/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_scan_router__AddFindingRequest = {
    /**
     * Short finding title
     */
    title: string;
    /**
     * critical | high | medium | low | info
     */
    severity: string;
    cve_id?: (string | null);
    cvss_score?: (number | null);
    /**
     * open | in_progress | resolved | accepted_risk | false_positive
     */
    finding_status?: string;
    affected_asset?: (string | null);
    plugin_id?: (string | null);
    description?: (string | null);
    remediation?: (string | null);
    detected_at?: (string | null);
};

