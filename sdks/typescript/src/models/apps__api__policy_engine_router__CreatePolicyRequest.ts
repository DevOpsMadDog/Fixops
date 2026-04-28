/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyDecision } from './PolicyDecision';
import type { PolicyLanguage } from './PolicyLanguage';
import type { PolicyScope } from './PolicyScope';
export type apps__api__policy_engine_router__CreatePolicyRequest = {
    name: string;
    description?: string;
    scope: PolicyScope;
    language?: PolicyLanguage;
    rules?: Array<Record<string, any>>;
    decision_on_match?: PolicyDecision;
    enabled?: boolean;
};

