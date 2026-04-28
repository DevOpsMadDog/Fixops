/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__runtime_protection__PolicyAction } from './core__runtime_protection__PolicyAction';
import type { EventType } from './EventType';
/**
 * Request body for creating a custom runtime policy.
 */
export type apps__api__runtime_protection_router__PolicyCreateRequest = {
    name: string;
    event_type: EventType;
    conditions?: Record<string, any>;
    action?: core__runtime_protection__PolicyAction;
    enabled?: boolean;
};

