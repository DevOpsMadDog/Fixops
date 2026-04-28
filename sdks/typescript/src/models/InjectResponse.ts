/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after injecting a synthetic vulnerability.
 */
export type InjectResponse = {
    drill_id: string;
    scenario_id: string;
    scenario_name: string;
    target_component: string;
    org_id: string;
    status: string;
    severity: string;
    synthetic_finding_id: string;
    injected_at?: (string | null);
    expires_at: string;
    message: string;
};

