/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ConnectRequest = {
    /**
     * ServiceNow instance URL (e.g., https://dev12345.service-now.com)
     */
    instance_url: string;
    /**
     * OAuth2 client ID
     */
    client_id?: string;
    /**
     * OAuth2 client secret
     */
    client_secret?: string;
    /**
     * Basic auth username (fallback)
     */
    username?: string;
    /**
     * Basic auth password (fallback)
     */
    password?: string;
    /**
     * Auth method: oauth2 or basic
     */
    auth_method?: string;
};

