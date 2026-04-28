/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AttributeAssetRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Opaque reference to the asset (e.g. domain, ID)
     */
    asset_ref: string;
    /**
     * Subsidiary / business-unit name
     */
    subsidiary_name: string;
    /**
     * Source of attribution: manual / whois / registration / heuristic
     */
    attribution_source: string;
    /**
     * Attribution confidence (0-1)
     */
    confidence?: number;
};

