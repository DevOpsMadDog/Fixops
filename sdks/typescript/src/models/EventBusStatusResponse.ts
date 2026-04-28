/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EventBusStatusResponse = {
    enabled: boolean;
    enabled_event_types: Array<string>;
    registered_handlers: Record<string, number>;
    metrics: Record<string, any>;
    queue: Record<string, any>;
};

