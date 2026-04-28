/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookTrigger } from './PlaybookTrigger';
/**
 * Body for evaluating an incoming security event against playbooks.
 */
export type apps__api__soar_router__TriggerEventRequest = {
    /**
     * Event trigger type
     */
    trigger: PlaybookTrigger;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Additional event context
     */
    event_data?: Record<string, any>;
};

