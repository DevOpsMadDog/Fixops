/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for scanning a Dockerfile.
 */
export type apps__api__container_scanner_router__ScanDockerfileRequest = {
    /**
     * Raw Dockerfile content to analyse
     */
    content: string;
    /**
     * Logical path for reporting
     */
    file_path?: string;
    /**
     * Organisation identifier for history scoping
     */
    org_id?: string;
};

