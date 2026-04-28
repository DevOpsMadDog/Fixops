/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { QuestionnaireResponse } from './QuestionnaireResponse';
/**
 * Request body for submitting questionnaire responses.
 */
export type QuestionnaireSubmitRequest = {
    responses: Array<QuestionnaireResponse>;
    /**
     * User or system submitting the responses
     */
    assessed_by?: string;
};

