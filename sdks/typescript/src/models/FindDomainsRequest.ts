/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FindDomainsRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Parent-org apex domain, e.g. acmecorp.com
     */
    parent_domain: string;
    /**
     * Optional seed substrings to boost confidence (e.g. subsidiary names)
     */
    seed_patterns?: Array<string>;
};

