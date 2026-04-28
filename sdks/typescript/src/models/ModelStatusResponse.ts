/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Status of a single ML model.
 */
export type ModelStatusResponse = {
    name: string;
    type: string;
    status: string;
    samples_trained?: number;
    accuracy?: number;
    last_trained?: (string | null);
    feature_names?: Array<string>;
};

