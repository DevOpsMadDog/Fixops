/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AdvisoryCreate = {
    advisory_id?: string;
    vendor: string;
    product?: string;
    severity?: string;
    advisory_url?: string;
    cves_covered?: Array<string>;
    patch_version?: string;
    release_date?: string;
    status?: string;
};

