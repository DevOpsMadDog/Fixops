/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_surface_mgmt_router__AssetCreate = {
    asset_type: string;
    value: string;
    parent_asset_id?: (string | null);
    status?: string;
    risk_score?: number;
    first_discovered?: (string | null);
    last_seen?: (string | null);
    tags?: Array<string>;
    notes?: string;
};

