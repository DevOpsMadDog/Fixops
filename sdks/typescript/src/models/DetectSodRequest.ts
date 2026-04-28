/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SodRule } from './SodRule';
export type DetectSodRequest = {
    /**
     * User ID to check
     */
    user_id: string;
    /**
     * List of SoD rules to evaluate
     */
    sod_rules: Array<SodRule>;
};

