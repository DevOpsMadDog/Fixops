/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__exposure_case_router__CreateCaseRequest = {
    title: string;
    description?: string;
    org_id?: string;
    /**
     * critical|high|medium|low|info
     */
    priority?: string;
    root_cve?: (string | null);
    root_cwe?: (string | null);
    root_component?: (string | null);
    affected_assets?: Array<string>;
    cluster_ids?: Array<string>;
    finding_count?: number;
    risk_score?: number;
    epss_score?: (number | null);
    in_kev?: boolean;
    blast_radius?: number;
    assigned_to?: (string | null);
    assigned_team?: (string | null);
    sla_due?: (string | null);
    tags?: Array<string>;
    metadata?: Record<string, any>;
};

