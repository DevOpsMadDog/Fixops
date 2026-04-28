/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ActionStatus } from './ActionStatus';
/**
 * Agent action response.
 */
export type ActionResponse = {
    id: string;
    session_id: string;
    action_type: string;
    status: ActionStatus;
    parameters: Record<string, any>;
    result?: (Record<string, any> | null);
    error?: (string | null);
    created_at: string;
    completed_at?: (string | null);
};

