/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__iam_policy_router__AccessReviewCreate = {
    /**
     * Policy being reviewed
     */
    policy_id: string;
    /**
     * Reviewer identity
     */
    reviewer: string;
    /**
     * approved / revoked / modified
     */
    outcome?: string;
    /**
     * Description of action taken
     */
    action_taken?: string;
    /**
     * ISO 8601 review date (defaults to now)
     */
    review_date?: (string | null);
};

