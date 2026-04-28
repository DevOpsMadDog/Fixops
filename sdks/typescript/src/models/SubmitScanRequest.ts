/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SubmitScanRequest = {
    /**
     * List of {name, version, license} dependency objects
     */
    dependencies?: Array<Record<string, any>>;
    /**
     * Number of direct dependencies
     */
    direct_count?: number;
    /**
     * Number of transitive dependencies
     */
    transitive_count?: number;
};

