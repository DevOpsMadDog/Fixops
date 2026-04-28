/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_posture_router__UpdateFindingStatusRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * New status: open, suppressed, resolved, false_positive
     */
    status: string;
    /**
     * Status update notes
     */
    notes?: string;
};

