/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { WorkflowResponse } from './WorkflowResponse';
/**
 * Paginated workflow response.
 */
export type PaginatedWorkflowResponse = {
    items: Array<WorkflowResponse>;
    total: number;
    limit: number;
    offset: number;
};

