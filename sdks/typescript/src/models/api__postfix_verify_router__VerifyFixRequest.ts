/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for POST /api/v1/verify/fix.
 *
 * Accepts the finding metadata, the original vulnerable code, and the
 * proposed fixed code.  language is required; all other fields have
 * sensible defaults so callers can omit optional context.
 */
export type api__postfix_verify_router__VerifyFixRequest = {
    /**
     * Identifier of the original finding (e.g. FIND-0042)
     */
    finding_id?: string;
    /**
     * Vulnerability category: sql_injection | xss | buffer_overflow | path_traversal | command_injection | deserialization | ssrf | open_redirect | xxe | ldap_injection | xpath_injection | ...
     */
    finding_type?: string;
    /**
     * Finding severity: critical | high | medium | low
     */
    severity?: string;
    /**
     * The vulnerable code before the fix was applied
     */
    original_code: string;
    /**
     * The proposed fixed code to verify
     */
    fixed_code: string;
    /**
     * Source language: python | javascript | typescript | java | go | c | csharp | ruby | php | rust
     */
    language: string;
    /**
     * Optional file path for additional context
     */
    file_path?: (string | null);
    /**
     * Optional surrounding code for richer analysis
     */
    context_code?: (string | null);
    /**
     * Optional dependency changes {package: new_version} introduced by the fix
     */
    dep_changes?: (Record<string, string> | null);
};

