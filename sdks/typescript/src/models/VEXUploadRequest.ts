/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Upload VEX document to apply analysis decisions in bulk.
 */
export type VEXUploadRequest = {
    /**
     * Target project name
     */
    project_name: string;
    project_version?: string;
    /**
     * CycloneDX VEX JSON document as string
     */
    vex: string;
};

