/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Submit actual outcome for a council verdict to drive calibration.
 */
export type apps__api__council_enhanced_router__FeedbackRequest = {
    /**
     * verdict_id from CouncilVerdict
     */
    verdict_id: string;
    /**
     * Ground-truth label: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW
     */
    actual_outcome: string;
};

