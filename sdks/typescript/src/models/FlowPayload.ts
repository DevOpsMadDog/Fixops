/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /flows/register — register a new data flow.
 */
export type FlowPayload = {
    source: Record<string, any>;
    processors?: Array<Record<string, any>>;
    destination: Record<string, any>;
    data_categories: Array<string>;
};

