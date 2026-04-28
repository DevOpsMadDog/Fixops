/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ActivityType } from './ActivityType';
/**
 * Payload for recording a user activity event.
 */
export type apps__api__user_analytics_router__RecordActivityRequest = {
    /**
     * User email address
     */
    user_email: string;
    activity_type: ActivityType;
    /**
     * API endpoint path, if applicable
     */
    endpoint?: (string | null);
    /**
     * Feature name, if applicable
     */
    feature?: (string | null);
    /**
     * Arbitrary event metadata
     */
    metadata?: Record<string, any>;
    /**
     * Client IP address
     */
    ip_address?: string;
    /**
     * Organization ID for multi-tenancy
     */
    org_id?: string;
};

