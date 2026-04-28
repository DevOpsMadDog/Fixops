/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Lightweight app listing entry.
 */
export type AppSummary = {
    app_id: string;
    name: string;
    org_id: (string | null);
    criticality: string;
    data_classification: string;
    compliance: Array<string>;
    component_count: number;
    created_at: (string | null);
    updated_at: (string | null);
};

