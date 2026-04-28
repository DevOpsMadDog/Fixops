/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for POST /evaluate.
 *
 * Optional list of entity attribute payloads to register first, then evaluate.
 * Each entry needs ``entity_ref`` and ``attributes``.
 */
export type EvaluateBody = {
    entities?: Array<Record<string, any>>;
};

