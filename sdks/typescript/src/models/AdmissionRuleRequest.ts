/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AdmissionRuleRequest = {
    /**
     * Unique rule name
     */
    name: string;
    /**
     * Human-readable description
     */
    description?: string;
    /**
     * Action on violation: deny | warn | audit
     */
    action?: string;
    enabled?: boolean;
    conditions?: Record<string, any>;
};

