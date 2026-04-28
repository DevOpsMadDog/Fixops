/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntTriggerType } from './HuntTriggerType';
/**
 * Body for starting a new hunt workflow.
 */
export type apps__api__threat_hunter_router__StartHuntRequest = {
    /**
     * ID of the hypothesis to hunt against
     */
    hypothesis_id: string;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Analyst name or user ID
     */
    analyst?: string;
    /**
     * What initiated this hunt
     */
    trigger_type?: HuntTriggerType;
    /**
     * Additional context about the trigger
     */
    trigger_context?: Record<string, any>;
};

