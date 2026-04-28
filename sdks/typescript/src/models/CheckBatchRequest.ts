/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BatchResource } from './BatchResource';
export type CheckBatchRequest = {
    /**
     * Resources to check
     */
    resources: Array<BatchResource>;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

