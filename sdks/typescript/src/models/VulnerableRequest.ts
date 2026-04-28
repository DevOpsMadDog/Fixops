/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type VulnerableRequest = {
    org_id?: string;
    cve_id: string;
    /**
     * SQL LIKE pattern, e.g. 'requests.Session.mount' or 'requests.%'
     */
    dependency_fqn_pattern: string;
};

