/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for generating a CycloneDX SBOM from a local manifest.
 */
export type SBOMGenerateRequest = {
    /**
     * Filesystem path to requirements.txt or package.json
     */
    manifest_path: string;
    /**
     * Project name for SBOM metadata
     */
    project_name?: string;
    /**
     * Project version for SBOM metadata
     */
    project_version?: string;
};

