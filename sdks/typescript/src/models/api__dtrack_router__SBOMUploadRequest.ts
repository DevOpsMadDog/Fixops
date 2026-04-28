/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Upload SBOM via JSON body (alternative to file upload).
 */
export type api__dtrack_router__SBOMUploadRequest = {
    /**
     * Target project name in Dependency-Track
     */
    project_name: string;
    /**
     * Project version tag
     */
    project_version?: string;
    /**
     * Raw CycloneDX/SPDX JSON or XML as string
     */
    sbom: string;
    /**
     * Auto-create project if it doesn't exist
     */
    auto_create?: boolean;
};

