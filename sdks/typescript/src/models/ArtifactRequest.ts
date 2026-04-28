/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ArtifactRequest = {
    /**
     * Producing step_id (optional)
     */
    step_id?: (string | null);
    /**
     * Registry path / file path / package ref
     */
    artifact_ref: string;
    /**
     * container-image|binary|package|sbom|attestation
     */
    artifact_type: string;
    /**
     * SHA-256 of artifact
     */
    sha256: string;
    size_bytes?: number;
    /**
     * Signer identity (cosign sub, KMS key)
     */
    signed_by?: string;
    /**
     * e.g. sigstore, rsa-sha256, ed25519
     */
    signature_algo?: string;
};

