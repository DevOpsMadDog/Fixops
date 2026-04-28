/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ExposureLayerRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Opaque reference to the asset
     */
    asset_ref: string;
    /**
     * Network-zone tag: external-internet / dmz / internal / restricted / isolated
     */
    exposure_layer: string;
};

