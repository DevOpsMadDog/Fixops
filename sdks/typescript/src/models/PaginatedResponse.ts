/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApplicationResponse } from './ApplicationResponse';
/**
 * Paginated response wrapper.
 */
export type PaginatedResponse = {
    items: Array<ApplicationResponse>;
    total: number;
    limit: number;
    offset: number;
};

