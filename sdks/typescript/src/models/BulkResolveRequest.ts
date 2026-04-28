/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__upgrade_path_router__FindingItem } from './apps__api__upgrade_path_router__FindingItem';
export type BulkResolveRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Batch of findings
     */
    findings: Array<apps__api__upgrade_path_router__FindingItem>;
};

