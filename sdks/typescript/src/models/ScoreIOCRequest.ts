/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScoreIOCRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * The IOC value (IP, domain, hash, etc.)
     */
    ioc_value: string;
    /**
     * Type: ip/domain/url/hash/email/asn/cidr/user_agent
     */
    ioc_type?: string;
    /**
     * Name of the contributing source
     */
    source_name: string;
    /**
     * Source confidence for this IOC (0.0–1.0)
     */
    source_confidence: number;
};

