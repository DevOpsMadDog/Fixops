/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CSPMSnapshotScanRequest = {
    /**
     * aws|azure|gcp|kubernetes
     */
    cloud: string;
    /**
     * Account / subscription / project id
     */
    account_id: string;
    /**
     * Existing snapshot to scan
     */
    snapshot_id?: (string | null);
    regions?: Array<string>;
};

