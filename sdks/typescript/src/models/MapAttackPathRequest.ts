/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MapAttackPathRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Internet-facing entry point asset ID
     */
    entry_asset_id: string;
    /**
     * Internal target asset ID
     */
    target_asset_id: string;
    /**
     * Intermediate hop asset IDs
     */
    hops?: (Array<string> | null);
    /**
     * Network protocol
     */
    protocol?: string;
    /**
     * MITRE ATT&CK technique IDs
     */
    techniques?: (Array<string> | null);
};

