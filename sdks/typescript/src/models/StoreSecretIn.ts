/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type StoreSecretIn = {
    /**
     * Human-readable secret name
     */
    name: string;
    /**
     * api_key|password|certificate|token|ssh_key|database
     */
    secret_type?: string;
    /**
     * Vault path or location reference
     */
    path?: string;
    /**
     * Arbitrary tags
     */
    tags?: Array<string>;
    /**
     * Rotation interval in days
     */
    rotation_days?: number;
};

