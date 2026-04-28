/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__session_router__SessionResponse } from './apps__api__session_router__SessionResponse';
/**
 * Single suspicious session entry.
 */
export type SuspiciousSessionEntry = {
    user_email: string;
    reason: string;
    distinct_ips: Array<string>;
    distinct_agents: Array<string>;
    sessions: Array<apps__api__session_router__SessionResponse>;
};

