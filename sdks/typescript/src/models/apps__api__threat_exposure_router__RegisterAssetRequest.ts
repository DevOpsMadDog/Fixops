/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_exposure_router__RegisterAssetRequest = {
    org_id?: string;
    /**
     * Unique asset identifier
     */
    asset_id: string;
    /**
     * Human-readable asset name
     */
    asset_name: string;
    /**
     * host/application/network/cloud/user/api
     */
    asset_type?: string;
    /**
     * Known vulnerability count
     */
    vuln_count?: number;
};

