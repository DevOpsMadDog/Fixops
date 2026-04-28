/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DriftCheckRequest = {
    /**
     * IaC filenames to load from disk for drift check
     */
    filenames?: Array<string>;
    /**
     * Simulated cloud state: resource_name -> properties dict
     */
    cloud_state?: Record<string, any>;
};

