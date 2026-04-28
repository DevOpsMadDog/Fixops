/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookResponse } from './PlaybookResponse';
/**
 * Paginated response for playbooks.
 */
export type PaginatedPlaybooksResponse = {
    items: Array<PlaybookResponse>;
    total: number;
    page: number;
    page_size: number;
};

