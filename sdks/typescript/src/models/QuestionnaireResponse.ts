/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vendor's response to a single assessment question.
 */
export type QuestionnaireResponse = {
    question_id: string;
    /**
     * True = Yes, False = No
     */
    answer: boolean;
    /**
     * URL to supporting evidence
     */
    evidence_url?: (string | null);
    /**
     * Vendor-provided notes
     */
    notes?: (string | null);
};

