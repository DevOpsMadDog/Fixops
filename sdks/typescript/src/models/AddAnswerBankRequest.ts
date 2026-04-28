/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { QuestionCategory } from './QuestionCategory';
export type AddAnswerBankRequest = {
    /**
     * Canonical question text (lowercase)
     */
    question_key: string;
    category: QuestionCategory;
    answer: string;
    evidence_refs?: (Array<string> | null);
    confidence?: number;
    org_id?: string;
};

