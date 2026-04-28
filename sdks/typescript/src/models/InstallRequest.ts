/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for installing a marketplace app.
 */
export type InstallRequest = {
    /**
     * App-specific configuration
     */
    config?: Record<string, any>;
    /**
     * User or service account performing install
     */
    installed_by: string;
};

