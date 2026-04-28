/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__session_router__SessionResponse } from './apps__api__session_router__SessionResponse';
/**
 * Concurrent session detection result.
 */
export type ConcurrentSessionsResponse = {
    user_email: string;
    has_concurrent: boolean;
    session_count: number;
    sessions: Array<apps__api__session_router__SessionResponse>;
};

