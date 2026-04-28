/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Code analysis finding.
 */
export type Finding = {
    rule_id: string;
    message: string;
    severity: string;
    category: string;
    line: number;
    column: number;
    end_line?: (number | null);
    end_column?: (number | null);
    cwe_id?: (string | null);
    fix_suggestion?: (string | null);
    code_snippet?: (string | null);
};

