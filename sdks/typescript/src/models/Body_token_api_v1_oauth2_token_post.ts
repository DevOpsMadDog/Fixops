/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type Body_token_api_v1_oauth2_token_post = {
    /**
     * API Key ID (ak_…)
     */
    client_id: string;
    /**
     * Raw API key (aldeci_…)
     */
    client_secret: string;
    /**
     * Must be 'client_credentials' if provided
     */
    grant_type?: (string | null);
};

