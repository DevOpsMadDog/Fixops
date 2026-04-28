/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__Severity } from './apps__api__pr_gate_router__Severity';
/**
 * A security finding to evaluate.
 */
export type apps__api__pr_gate_router__FindingInput = {
    /**
     * Finding identifier
     */
    id: string;
    /**
     * Finding title
     */
    title: string;
    /**
     * Finding severity
     */
    severity: apps__api__pr_gate_router__Severity;
    /**
     * Finding category (sast, dast, secret, sca, iac)
     */
    category?: string;
    /**
     * File path where finding occurs
     */
    file_path?: (string | null);
    /**
     * Line number in file
     */
    line_number?: (number | null);
    /**
     * End line number
     */
    end_line?: (number | null);
    /**
     * Finding description
     */
    description?: (string | null);
    /**
     * Remediation guidance
     */
    remediation?: (string | null);
    /**
     * CVE identifier if applicable
     */
    cve_id?: (string | null);
    /**
     * CWE identifier
     */
    cwe_id?: (string | null);
    /**
     * Whether the finding is reachable from entry points
     */
    reachable?: (boolean | null);
    /**
     * Detection confidence
     */
    confidence?: number;
};

