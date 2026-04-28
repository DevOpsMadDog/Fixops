/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordCompletionRequest = {
    /**
     * User's email address
     */
    user_email: string;
    /**
     * Training module ID
     */
    module_id: string;
    /**
     * Score achieved (0-100)
     */
    score: number;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Completion timestamp (defaults to now)
     */
    completed_at?: (string | null);
};

