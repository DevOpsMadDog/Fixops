/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GitHubAppRegisterRequest = {
    org_id: string;
    app_id: string;
    installation_id: string;
    /**
     * Raw webhook secret. Stored hashed (SHA-256). GitHub's X-Hub-Signature-256 must be computed using this secret as the HMAC key.
     */
    webhook_secret: string;
    app_slug?: (string | null);
};

