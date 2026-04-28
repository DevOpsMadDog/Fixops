/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LifecycleStage } from './LifecycleStage';
/**
 * Request body for a lifecycle transition.
 */
export type apps__api__vuln_lifecycle_router__TransitionRequest = {
    /**
     * Target lifecycle stage
     */
    to_stage: LifecycleStage;
    /**
     * User or system triggering the change
     */
    changed_by: string;
    /**
     * Reason or notes for the transition
     */
    reason?: string;
};

