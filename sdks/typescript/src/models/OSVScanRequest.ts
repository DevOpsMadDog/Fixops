/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for an OSV vulnerability scan of listed packages.
 */
export type OSVScanRequest = {
    /**
     * List of {name, version, ecosystem} dicts. ecosystem: PyPI|npm|Go|Maven
     */
    packages: Array<Record<string, string>>;
};

