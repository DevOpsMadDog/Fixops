/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for bulk status update.
 */
export type apps__api__bulk_router__BulkStatusUpdateRequest = {
    ids: Array<string>;
    new_status: string;
    reason?: (string | null);
    changed_by?: (string | null);
};

