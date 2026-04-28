/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Blast radius analysis response.
 */
export type ImpactResponse = {
    entity_id: string;
    available: boolean;
    blast_radius: number;
    upstream_dependencies?: Array<Record<string, any>>;
    downstream_consumers?: Array<Record<string, any>>;
    data_flows?: Array<Record<string, any>>;
    compliance_impact?: Array<Record<string, any>>;
    risk_weight?: number;
    summary?: string;
};

