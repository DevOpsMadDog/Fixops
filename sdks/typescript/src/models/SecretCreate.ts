/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SecretCreate = {
    /**
     * Secret name / identifier
     */
    name: string;
    /**
     * api_key|db_password|tls_cert|oauth_token|ssh_key|service_account
     */
    secret_type?: string;
    /**
     * Owner team or user
     */
    owner?: string;
    /**
     * prod|staging|dev
     */
    environment?: string;
    /**
     * Days between required rotations
     */
    rotation_days?: number;
    /**
     * Unix timestamp of expiry (computed if omitted)
     */
    expires_at?: (number | null);
    /**
     * Unix timestamp of last rotation
     */
    last_rotated?: (number | null);
    org_id?: string;
};

