/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Result of validating a security tool output.
 */
export type ValidationResult = {
    valid: boolean;
    input_type: string;
    detected_format?: (string | null);
    detected_version?: (string | null);
    tool_name?: (string | null);
    findings_count?: number;
    components_count?: number;
    warnings?: Array<string>;
    errors?: Array<string>;
    metadata?: Record<string, any>;
    file_info?: Record<string, any>;
    compatibility?: Record<string, any>;
};

