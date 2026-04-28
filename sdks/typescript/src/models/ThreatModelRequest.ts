/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for threat model definition.
 */
export type ThreatModelRequest = {
    /**
     * Name of the threat model
     */
    name: string;
    /**
     * Description
     */
    description?: string;
    /**
     * Threat categories
     */
    categories?: Array<string>;
    /**
     * Attack vectors
     */
    attack_vectors?: Array<string>;
    /**
     * Compliance frameworks
     */
    compliance_frameworks?: Array<string>;
    /**
     * Priority (1-10)
     */
    priority?: number;
};

