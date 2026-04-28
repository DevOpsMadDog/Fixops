/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after SBOM ingestion.
 */
export type SBOMUploadResponse = {
    sbom_id: string;
    format: string;
    name: string;
    version: string;
    component_count: number;
    sha256: string;
    attack_signals_detected: number;
    org_id: string;
};

