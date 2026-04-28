/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookTrigger } from './PlaybookTrigger';
/**
 * Body for creating a new SOAR playbook.
 */
export type apps__api__soar_router__CreatePlaybookRequest = {
    /**
     * Human-readable playbook name
     */
    name: string;
    /**
     * Event type that fires this playbook
     */
    trigger: PlaybookTrigger;
    /**
     * Ordered list of action definitions
     */
    actions: Array<Record<string, any>>;
    /**
     * Optional key/value conditions that must match the event
     */
    conditions?: Record<string, any>;
    /**
     * Whether the playbook is active
     */
    enabled?: boolean;
    /**
     * Organisation ID
     */
    org_id?: string;
};

