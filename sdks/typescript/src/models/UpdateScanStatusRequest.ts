/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateScanStatusRequest = {
    /**
     * pending | running | completed | failed | cancelled
     */
    new_status: string;
    completed_at?: (string | null);
};

