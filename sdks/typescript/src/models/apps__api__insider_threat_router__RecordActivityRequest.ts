/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for recording a user activity event.
 */
export type apps__api__insider_threat_router__RecordActivityRequest = {
    /**
     * User's email address
     */
    user_email: string;
    /**
     * Activity type, e.g. 'data_download', 'sudo'
     */
    activity_type: string;
    /**
     * Arbitrary context (bytes_transferred, resource, etc.)
     */
    details?: Record<string, any>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

