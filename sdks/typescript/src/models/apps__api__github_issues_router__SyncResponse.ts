/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SyncResultItem } from './SyncResultItem';
export type apps__api__github_issues_router__SyncResponse = {
    total: number;
    succeeded: number;
    failed: number;
    push_results?: Array<SyncResultItem>;
    pull_results?: Array<Record<string, any>>;
};

