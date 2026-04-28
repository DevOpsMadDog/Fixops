/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRiskThresholdRequest = {
    /**
     * asset | user | network | application | vendor
     */
    entity_type?: string;
    /**
     * Score threshold 0-100
     */
    threshold?: number;
    /**
     * alert | escalate | block
     */
    action?: string;
};

