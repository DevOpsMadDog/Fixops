/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for scanning a Docker image.
 */
export type apps__api__trivy_router__ScanImageRequest = {
    /**
     * Docker image reference, e.g. nginx:latest
     */
    image: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

