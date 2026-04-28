/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookRunResponse } from './PlaybookRunResponse';
/**
 * Paginated response for playbook runs.
 */
export type PaginatedRunsResponse = {
    items: Array<PlaybookRunResponse>;
    total: number;
    page: number;
    page_size: number;
};

