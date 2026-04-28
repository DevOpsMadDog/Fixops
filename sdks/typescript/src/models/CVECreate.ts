/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CVECreate = {
    cve_id: string;
    title?: string;
    description?: string;
    cvss_score?: number;
    cvss_vector?: string;
    epss_score?: number;
    kev_listed?: boolean;
    kev_added_date?: (string | null);
    severity?: string;
    affected_products?: Array<any>;
    exploit_available?: boolean;
    exploit_type?: (string | null);
    patch_available?: boolean;
    patch_url?: string;
    references?: Array<string>;
    threat_actors_using?: Array<string>;
    affected_org_assets?: Array<string>;
    status?: string;
};

