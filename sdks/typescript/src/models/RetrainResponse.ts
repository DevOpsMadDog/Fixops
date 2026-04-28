/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for ML model retraining.
 */
export type RetrainResponse = {
    job_id: string;
    status: string;
    models_queued: Array<string>;
    estimated_time: string;
    data_points: number;
};

