/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntTriggerType } from './HuntTriggerType';
/**
 * Body for firing an automated hunt trigger.
 */
export type FireTriggerRequest = {
    trigger_type: HuntTriggerType;
    context?: Record<string, any>;
    org_id?: string;
};

