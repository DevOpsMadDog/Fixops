/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_risk_router__ScoreResponse = {
    cve_id: string;
    org_id: string;
    composite_score: number;
    priority: string;
    factors: Record<string, any>;
    recommendation: string;
    sla_hours: number;
    record_id?: (string | null);
};

