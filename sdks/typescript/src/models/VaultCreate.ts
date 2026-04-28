/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type VaultCreate = {
    /**
     * Human-readable vault name
     */
    name: string;
    /**
     * hashicorp|aws_secrets|azure_kv|gcp_sm|local
     */
    vault_type?: string;
    /**
     * active|locked
     */
    status?: string;
    org_id?: string;
};

