/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateMitigationRequest = {
    /**
     * Short mitigation title
     */
    title: string;
    description?: (string | null);
    /**
     * planned | in_progress | completed | deferred
     */
    mitigation_status?: string;
    assigned_to?: (string | null);
    due_date?: (string | null);
    completed_at?: (string | null);
};

