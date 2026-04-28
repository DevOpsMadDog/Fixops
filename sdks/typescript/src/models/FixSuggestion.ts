/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Actionable fix suggestion for a security finding.
 */
export type FixSuggestion = {
    finding_id: string;
    title: string;
    description: string;
    code_snippet?: (string | null);
    upgrade_command?: (string | null);
    reference_url: string;
    /**
     * One of: easy, medium, hard
     */
    difficulty: string;
    estimated_time_minutes: number;
};

