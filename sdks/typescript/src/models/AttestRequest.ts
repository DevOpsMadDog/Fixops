/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AttestRequest = {
    /**
     * Organisation ID (multi-tenant isolation)
     */
    org_id: string;
    /**
     * Name of the subject — typically a container image reference or artifact URL
     */
    subject_name: string;
    /**
     * SHA-256 digest of the subject artifact
     */
    subject_sha256: string;
    /**
     * URI identifying the build platform (e.g. https://github.com/actions/runner)
     */
    builder_id: string;
    /**
     * URI identifying the build process schema (e.g. https://slsa.dev/container-based-build/v0.1?draft)
     */
    build_type: string;
    /**
     * Build invocation metadata (configSource, parameters, environment)
     */
    invocation?: Record<string, any>;
    /**
     * List of build-input materials (source repos, base images, etc.)
     */
    materials?: Array<Record<string, any>>;
    /**
     * Optional invocation metadata (buildStartedOn, reproducible, etc.)
     */
    metadata?: Record<string, any>;
    /**
     * Target SLSA level 1-4 per SLSA v1.0 spec
     */
    slsa_level?: number;
};

