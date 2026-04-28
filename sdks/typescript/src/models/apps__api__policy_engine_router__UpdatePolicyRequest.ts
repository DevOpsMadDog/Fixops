/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyDecision } from './PolicyDecision';
import type { PolicyLanguage } from './PolicyLanguage';
import type { PolicyScope } from './PolicyScope';
export type apps__api__policy_engine_router__UpdatePolicyRequest = {
    name?: (string | null);
    description?: (string | null);
    scope?: (PolicyScope | null);
    language?: (PolicyLanguage | null);
    rules?: null;
    decision_on_match?: (PolicyDecision | null);
    enabled?: (boolean | null);
};

