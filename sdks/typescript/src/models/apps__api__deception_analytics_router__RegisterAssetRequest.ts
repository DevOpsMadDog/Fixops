/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__deception_analytics_router__RegisterAssetRequest = {
    /**
     * Human-readable asset name
     */
    asset_name: string;
    /**
     * honeypot | honeytoken | canary_file | canary_cred | fake_service | honey_user | lure_document | breadcrumb
     */
    asset_type?: string;
    /**
     * Asset location (IP, path, URL)
     */
    location?: string;
    /**
     * network | endpoint | cloud | identity | data | application
     */
    decoy_category?: string;
    active?: boolean;
};

