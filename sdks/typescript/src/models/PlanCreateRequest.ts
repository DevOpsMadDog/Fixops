/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__patch_prioritizer_router__ScoreRequest } from './apps__api__patch_prioritizer_router__ScoreRequest';
export type PlanCreateRequest = {
    cves: Array<apps__api__patch_prioritizer_router__ScoreRequest>;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Human-readable plan name
     */
    plan_name?: string;
};

