/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /registries/scan — assess registry security posture.
 */
export type RegistryScanRequest = {
    registry_url: string;
    registry_metadata?: (Record<string, any> | null);
    images?: null;
};

