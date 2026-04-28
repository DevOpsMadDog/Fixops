/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddControlBody = {
    /**
     * Control name or identifier
     */
    control_name: string;
    /**
     * Security domain (e.g. IAM, Network, Crypto)
     */
    domain: string;
    /**
     * implemented | partial | not_implemented | compensating
     */
    implementation_status?: string;
    /**
     * Effectiveness score 0–100
     */
    effectiveness?: number;
    /**
     * Description of gaps
     */
    gaps?: string;
};

