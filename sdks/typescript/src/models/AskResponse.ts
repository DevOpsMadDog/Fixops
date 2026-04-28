/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AskReference } from './AskReference';
/**
 * Response from the /ask endpoint.
 */
export type AskResponse = {
    /**
     * Plain-English explanation of the vulnerability or security insight
     */
    answer: string;
    /**
     * Authoritative external references
     */
    references?: Array<AskReference>;
    /**
     * Concrete remediation guidance or code snippet
     */
    suggested_fix?: string;
    /**
     * Typical severity level: critical / high / medium / low
     */
    severity_context?: string;
    /**
     * Related findings from the current session (if context provided)
     */
    related_findings?: Array<Record<string, any>>;
    /**
     * CWE identifier that best matched the question
     */
    matched_cwe?: (string | null);
    /**
     * Origin of the answer (builtin_knowledge_base | graphrag_security_insight | llm_enhanced)
     */
    source?: string;
    /**
     * Detected security-ops intent (top_risks | compliance | threat_landscape | attack_surface)
     */
    intent?: (string | null);
    /**
     * Recommended follow-up actions with API endpoints
     */
    recommended_actions?: Array<Record<string, string>>;
    /**
     * Answer confidence score (0.0-1.0); higher when GraphRAG found relevant entities
     */
    confidence?: number;
};

