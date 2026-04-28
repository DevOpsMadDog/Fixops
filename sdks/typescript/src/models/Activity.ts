/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ActivityType } from './ActivityType';
/**
 * A single recorded user activity event.
 */
export type Activity = {
    id?: string;
    user_email: string;
    activity_type: ActivityType;
    endpoint?: (string | null);
    feature?: (string | null);
    metadata?: Record<string, any>;
    ip_address?: string;
    timestamp?: string;
    org_id: string;
};

