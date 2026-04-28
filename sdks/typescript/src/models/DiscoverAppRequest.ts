/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DiscoverAppRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Cloud application name (e.g. 'Dropbox')
     */
    app_name: string;
    /**
     * Category: productivity/collaboration/storage/crm/devtools/social/other
     */
    app_category?: string;
    /**
     * Risk level: critical/high/medium/low
     */
    risk_level?: string;
    /**
     * Number of users using the app
     */
    users_count?: number;
    /**
     * Data uploaded in GB
     */
    data_uploaded_gb?: number;
    /**
     * Whether the app is sanctioned
     */
    is_sanctioned?: boolean;
    /**
     * OAuth permission scopes granted
     */
    oauth_scopes?: Array<string>;
};

