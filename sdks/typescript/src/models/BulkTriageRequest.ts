/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for POST /api/v1/alert-triage/bulk-triage.
 *
 * Validation rules (enforced by Pydantic before reaching the route handler):
 * * ``alert_ids`` (or ``alert_id``) must be supplied and non-empty.
 * * Every ID must be a non-empty, whitespace-stripped string.
 * * Duplicates are removed while preserving caller order.
 * * ``action`` must be one of: acknowledge | ack | resolve | false_positive | escalate.
 */
export type BulkTriageRequest = {
    /**
     * List of alert IDs to action (1-500 entries)
     */
    alert_ids?: (Array<string> | null);
    /**
     * Single alert ID (convenience alias for alert_ids)
     */
    alert_id?: (string | null);
    /**
     * acknowledge | ack | resolve | false_positive | escalate
     */
    action: BulkTriageRequest.action;
    /**
     * Organization ID (can also be passed as query param)
     */
    org_id?: (string | null);
};
export namespace BulkTriageRequest {
    /**
     * acknowledge | ack | resolve | false_positive | escalate
     */
    export enum action {
        ACKNOWLEDGE = 'acknowledge',
        ACK = 'ack',
        RESOLVE = 'resolve',
        FALSE_POSITIVE = 'false_positive',
        ESCALATE = 'escalate',
    }
}

