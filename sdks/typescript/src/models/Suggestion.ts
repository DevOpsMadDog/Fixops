/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Code improvement suggestion.
 */
export type Suggestion = {
    type: string;
    message: string;
    line: number;
    priority: string;
    auto_fixable?: boolean;
    fix_code?: (string | null);
};

