/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateWorkflowStatusRequest = {
    /**
     * open | assigned | in_progress | pending_verification | verified | closed | cancelled
     */
    status: string;
    /**
     * Status-change notes
     */
    notes?: (string | null);
};

