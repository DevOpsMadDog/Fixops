/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for testing a single package.
 */
export type TestPackageRequest = {
    /**
     * Package ecosystem (npm, pip, maven, etc.)
     */
    ecosystem: string;
    /**
     * Package name
     */
    package: string;
    /**
     * Package version
     */
    version: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

