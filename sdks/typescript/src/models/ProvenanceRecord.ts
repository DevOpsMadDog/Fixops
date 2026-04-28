/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ProvenanceLevel } from './ProvenanceLevel';
/**
 * SLSA provenance / build attestation for a component.
 */
export type ProvenanceRecord = {
    id?: string;
    component_name: string;
    component_version: string;
    slsa_level?: ProvenanceLevel;
    /**
     * e.g. GitHub Actions, Jenkins
     */
    build_system?: (string | null);
    build_config_uri?: (string | null);
    builder_id?: (string | null);
    source_uri?: (string | null);
    source_digest?: (string | null);
    /**
     * Raw attestation JSON
     */
    attestation_payload?: (string | null);
    signature_verified?: boolean;
    signature_keyid?: (string | null);
    sigstore_bundle?: (string | null);
    verification_errors?: Array<string>;
    verified_at?: string;
};

