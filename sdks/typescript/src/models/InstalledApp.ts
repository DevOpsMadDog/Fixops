/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AppStatus } from './AppStatus';
/**
 * An integration installed by an organization.
 */
export type InstalledApp = {
    /**
     * References MarketplaceApp.id
     */
    app_id: string;
    /**
     * Organization that installed the app
     */
    org_id: string;
    /**
     * Runtime configuration (API keys, URLs, etc.)
     */
    config?: Record<string, any>;
    /**
     * When the app was installed
     */
    installed_at?: string;
    status?: AppStatus;
    /**
     * User ID or service account that installed the app
     */
    installed_by: string;
};

