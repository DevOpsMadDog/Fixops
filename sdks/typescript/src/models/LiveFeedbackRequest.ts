/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Submit a single feedback item for any loop and immediately see the scoring effect.
 */
export type LiveFeedbackRequest = {
    /**
     * Loop name: decision, mpte, fp, remediation, policy
     */
    loop: string;
    /**
     * Decision ID (for decision loop)
     */
    decision_id?: string;
    /**
     * Finding ID
     */
    finding_id?: string;
    /**
     * What AI decided
     */
    predicted_action?: string;
    /**
     * What actually happened
     */
    actual_outcome?: string;
    /**
     * Was it predicted exploitable?
     */
    predicted_exploitable?: boolean;
    /**
     * Was it actually exploitable?
     */
    actual_exploitable?: boolean;
    mpte_confidence?: number;
    /**
     * Scanner name
     */
    scanner?: string;
    /**
     * Rule ID
     */
    rule_id?: string;
    /**
     * Is this a false positive?
     */
    is_false_positive?: boolean;
    /**
     * Fix type
     */
    fix_type?: string;
    /**
     * Fix description
     */
    fix_applied?: string;
    /**
     * Did the fix resolve the issue?
     */
    resolved?: boolean;
    time_to_fix_hours?: number;
    /**
     * Policy ID
     */
    policy_id?: string;
    /**
     * Was the policy violated?
     */
    violated?: boolean;
    /**
     * Was the violation justified?
     */
    was_justified?: boolean;
    cvss_score?: number;
    epss_score?: number;
    in_kev?: boolean;
    asset_criticality?: number;
};

