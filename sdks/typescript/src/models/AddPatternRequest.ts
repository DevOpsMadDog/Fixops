/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddPatternRequest = {
    /**
     * Unique pattern name
     */
    name: string;
    /**
     * Python regex pattern string
     */
    pattern: string;
    /**
     * Severity: low | medium | high | critical
     */
    severity: string;
    /**
     * Category label (e.g. pii, pci, credentials)
     */
    category: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

