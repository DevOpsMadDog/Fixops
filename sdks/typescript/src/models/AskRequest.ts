/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AskContext } from './AskContext';
/**
 * Stateless security question for the copilot /ask endpoint.
 */
export type AskRequest = {
    /**
     * Natural-language security question
     */
    question: string;
    /**
     * Optional structured context to improve answer relevance
     */
    context?: (AskContext | null);
};

