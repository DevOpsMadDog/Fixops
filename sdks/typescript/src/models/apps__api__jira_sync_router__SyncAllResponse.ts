/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__jira_sync_router__SyncResultResponse } from './apps__api__jira_sync_router__SyncResultResponse';
export type apps__api__jira_sync_router__SyncAllResponse = {
    total: number;
    succeeded: number;
    failed: number;
    skipped: number;
    results: Array<apps__api__jira_sync_router__SyncResultResponse>;
};

