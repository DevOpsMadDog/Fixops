/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssignTrainingRequest = {
    /**
     * User ID to assign training to
     */
    user_id: string;
    /**
     * Module ID (e.g. 'phishing-awareness')
     */
    module: string;
    /**
     * Assignment due date (ISO 8601)
     */
    due_date?: (string | null);
};

