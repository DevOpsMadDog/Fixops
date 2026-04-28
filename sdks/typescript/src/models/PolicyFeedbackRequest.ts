/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PolicyFeedbackRequest = {
    /**
     * Policy ID
     */
    policy_id: string;
    /**
     * Rule ID within policy
     */
    rule_id: string;
    /**
     * Was the policy violated?
     */
    violated: boolean;
    /**
     * Was the action justified?
     */
    was_justified: boolean;
    context?: Record<string, any>;
};

