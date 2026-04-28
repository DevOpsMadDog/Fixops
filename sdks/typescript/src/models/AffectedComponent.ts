/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Affected software/hardware component.
 */
export type AffectedComponent = {
    vendor: string;
    product: string;
    version: string;
    version_end?: (string | null);
    /**
     * CPE identifier if known
     */
    cpe?: (string | null);
};

