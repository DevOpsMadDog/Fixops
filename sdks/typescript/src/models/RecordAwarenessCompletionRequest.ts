/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAwarenessCompletionRequest = {
    /**
     * User ID
     */
    user_id: string;
    /**
     * Assignment ID returned from /assign
     */
    assignment_id: string;
    /**
     * Quiz score (0–100)
     */
    score: number;
};

