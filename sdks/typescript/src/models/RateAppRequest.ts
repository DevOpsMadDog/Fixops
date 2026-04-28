/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for rating an app.
 */
export type RateAppRequest = {
    user_id: string;
    /**
     * Rating between 1.0 and 5.0
     */
    score: number;
    /**
     * Optional review comment
     */
    comment?: (string | null);
};

