/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScoreFindingRequest = {
    /**
     * Finding identifier to score
     */
    finding_id: string;
    /**
     * CVE ID associated with finding
     */
    cve_id?: (string | null);
    /**
     * Asset affected by finding
     */
    asset_id?: (string | null);
};

