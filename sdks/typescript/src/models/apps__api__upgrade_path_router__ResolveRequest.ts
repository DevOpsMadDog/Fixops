/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__upgrade_path_router__ResolveRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Package URL, e.g. pkg:npm/lodash@4.17.19
     */
    purl: string;
    /**
     * CVE identifiers to resolve
     */
    cve_ids: Array<string>;
};

