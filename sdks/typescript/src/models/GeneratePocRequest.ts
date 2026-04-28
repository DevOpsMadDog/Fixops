/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to generate proof-of-concept.
 */
export type GeneratePocRequest = {
    cve_id: string;
    /**
     * python, go, bash
     */
    language?: string;
    safe_poc?: boolean;
};

