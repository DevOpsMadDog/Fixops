/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Single rule within a CI/CD policy.
 */
export type core__cicd_integration__PolicyRule = {
    /**
     * Human-readable rule name
     */
    name: string;
    /**
     * Block if any finding >= this severity (critical|high|medium|low)
     */
    severity_threshold?: string;
    /**
     * Max allowed critical findings before blocking
     */
    max_critical?: number;
    /**
     * Max allowed high findings before blocking
     */
    max_high?: number;
    /**
     * Only apply rule to these finding categories (empty = all)
     */
    categories?: Array<string>;
    /**
     * Whether this rule is active
     */
    enabled?: boolean;
};

