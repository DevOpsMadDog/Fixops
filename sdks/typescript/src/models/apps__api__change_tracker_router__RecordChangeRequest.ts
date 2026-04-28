/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ChangeRisk } from './ChangeRisk';
import type { core__change_tracker__ChangeType } from './core__change_tracker__ChangeType';
export type apps__api__change_tracker_router__RecordChangeRequest = {
    /**
     * Category of the change
     */
    type: core__change_tracker__ChangeType;
    /**
     * Human-readable description
     */
    description: string;
    /**
     * Who made the change (email or username)
     */
    author: string;
    /**
     * Impacted assets
     */
    affected_assets?: Array<string>;
    /**
     * Initial risk assessment
     */
    risk_level?: ChangeRisk;
    /**
     * Optional security impact note
     */
    security_impact?: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

