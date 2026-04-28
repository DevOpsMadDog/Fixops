/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ExposeRequest = {
    /**
     * One of: ['api_key', 'password', 'token', 'certificate', 'ssh_key', 'database_credential', 'oauth_secret']
     */
    secret_type: string;
    /**
     * File path, URL, or commit hash where secret was found
     */
    exposed_location: string;
    /**
     * Tool that detected the secret
     */
    detection_source?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
};

