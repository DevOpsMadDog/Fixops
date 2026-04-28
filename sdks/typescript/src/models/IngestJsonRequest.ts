/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IngestJsonRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Cloud provider: aws/azure/gcp
     */
    provider?: string;
    /**
     * Cloud account ID
     */
    account_id?: string;
    /**
     * Raw Prowler JSON output
     */
    raw_json: string;
};

