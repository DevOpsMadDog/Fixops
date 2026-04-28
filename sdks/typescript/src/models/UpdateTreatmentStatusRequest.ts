/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateTreatmentStatusRequest = {
    /**
     * planned | in_progress | completed | overdue
     */
    status: string;
    /**
     * ISO date when completed
     */
    completion_date?: string;
};

