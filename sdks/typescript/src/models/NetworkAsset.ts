/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetType } from './AssetType';
export type NetworkAsset = {
    id?: string;
    org_id: string;
    asset_type: AssetType;
    name: string;
    address: string;
    vlan_id?: (number | null);
    description?: (string | null);
    tags?: Array<string>;
    discovered_at?: string;
    last_seen?: string;
    metadata?: Record<string, any>;
};

