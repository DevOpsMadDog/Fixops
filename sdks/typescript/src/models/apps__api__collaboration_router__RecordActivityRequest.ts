/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to record an activity.
 */
export type apps__api__collaboration_router__RecordActivityRequest = {
    entity_type: string;
    entity_id: string;
    org_id: string;
    activity_type: string;
    actor: string;
    summary: string;
    actor_email?: (string | null);
    details?: (Record<string, any> | null);
};

