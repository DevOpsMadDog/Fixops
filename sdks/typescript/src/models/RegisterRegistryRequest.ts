/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterRegistryRequest = {
    /**
     * Registry display name
     */
    name: string;
    /**
     * Registry URL (e.g. registry.example.com)
     */
    url?: string;
    /**
     * One of: docker, ecr, gcr, acr, harbor
     */
    registry_type?: string;
    /**
     * Whether auth credentials are configured
     */
    auth_configured?: boolean;
};

