/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vendor assessment result.
 */
export type AssessmentResponse = {
    id: string;
    vendor_id: string;
    questionnaire_score: number;
    category_scores: Record<string, number>;
    question_count: number;
    submitted_at: string;
    next_review_date: (string | null);
    assessed_by: string;
};

