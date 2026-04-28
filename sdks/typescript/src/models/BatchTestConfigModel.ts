/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Configuration for a single test in a batch.
 *
 * Security: list size limits prevent DoS via huge batch payloads.
 */
export type BatchTestConfigModel = {
    /**
     * CVE IDs to test
     */
    cve_ids?: Array<string>;
    /**
     * Target URLs to test
     */
    target_urls?: Array<string>;
    /**
     * Optional context
     */
    context?: Record<string, any>;
};

