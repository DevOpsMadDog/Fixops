/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterComponentRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Project name
     */
    project_name: string;
    /**
     * Component name
     */
    component_name: string;
    /**
     * Component version
     */
    component_version: string;
    /**
     * library|framework|application|container|device|firmware|file|operating-system
     */
    component_type: string;
    /**
     * npm|pypi|maven|nuget|cargo|go|gem|composer
     */
    ecosystem?: string;
    /**
     * SPDX license identifier
     */
    license?: string;
    /**
     * Package URL
     */
    purl?: string;
    /**
     * CPE identifier
     */
    cpe?: string;
    /**
     * Supplier/vendor name
     */
    supplier?: string;
    /**
     * SHA-256 hash of component
     */
    hash_sha256?: string;
};

