/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssetRegister = {
    /**
     * Optional external asset ID
     */
    asset_id?: (string | null);
    /**
     * Human-readable asset name
     */
    asset_name: string;
    /**
     * server | workstation | network | application | database | cloud | iot | mobile | container
     */
    asset_type?: string;
    /**
     * mission_critical | high | medium | low
     */
    criticality?: string;
    owner?: string;
    environment?: string;
};

