/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LifecycleStage } from './LifecycleStage';
/**
 * Request body for transition validation.
 */
export type apps__api__vuln_lifecycle_router__ValidateRequest = {
    /**
     * Current stage (None for new findings)
     */
    from_stage?: (LifecycleStage | null);
    /**
     * Proposed next stage
     */
    to_stage: LifecycleStage;
};

