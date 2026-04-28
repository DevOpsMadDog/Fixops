/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetType } from './AssetType';
export type apps__api__network_security_router__RegisterAssetRequest = {
    /**
     * Human-readable asset name
     */
    name: string;
    /**
     * Type of network asset
     */
    asset_type: AssetType;
    /**
     * IP address, CIDR, or descriptive address
     */
    address: string;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * VLAN identifier
     */
    vlan_id?: (number | null);
    /**
     * Asset description
     */
    description?: (string | null);
    /**
     * Tags e.g. ['pci-cde', 'internet-facing']
     */
    tags?: Array<string>;
    metadata?: Record<string, any>;
};

