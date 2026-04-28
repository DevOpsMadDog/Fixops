/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateTaskStatusIn = {
    /**
     * open|in_progress|testing|resolved|accepted_risk|closed
     */
    status: string;
    /**
     * Optional notes for status change
     */
    notes?: string;
};

