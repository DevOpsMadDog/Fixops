/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAttackRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Protected resource UUID
     */
    resource_id: string;
    /**
     * volumetric | protocol | application | slowloris | amplification
     */
    attack_type: string;
    /**
     * List of attacking source IPs
     */
    source_ips?: Array<string>;
    /**
     * Peak attack volume in Gbps
     */
    peak_gbps?: number;
    /**
     * Attack duration in seconds
     */
    duration_seconds?: number;
    /**
     * detected | mitigating | mitigated
     */
    status?: string;
};

