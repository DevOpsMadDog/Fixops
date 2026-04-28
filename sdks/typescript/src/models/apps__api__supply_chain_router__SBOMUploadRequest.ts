/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for uploading an SBOM document.
 */
export type apps__api__supply_chain_router__SBOMUploadRequest = {
    /**
     * Raw CycloneDX or SPDX SBOM as a JSON object
     */
    sbom: Record<string, any>;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Git repository URL this SBOM was generated from
     */
    source_repo?: (string | null);
};

