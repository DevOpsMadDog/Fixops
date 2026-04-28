/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create a custom injection scenario.
 */
export type apps__api__fail_router__CreateScenarioRequest = {
    /**
     * Unique identifier for the scenario (snake_case)
     */
    scenario_id: string;
    /**
     * Human-readable scenario name
     */
    name: string;
    /**
     * Scenario description
     */
    description: string;
    /**
     * Severity level: critical, high, medium, low, info
     */
    severity?: string;
    /**
     * The synthetic finding payload to inject
     */
    synthetic_finding: Record<string, any>;
    /**
     * CWE identifiers
     */
    cwe_ids?: Array<string>;
    /**
     * MITRE ATT&CK technique IDs
     */
    mitre_techniques?: Array<string>;
    /**
     * MITRE ATT&CK tactics
     */
    mitre_tactics?: Array<string>;
    /**
     * Target detection time in minutes
     */
    expected_detection_minutes?: number;
    /**
     * Expected triage classification for scoring
     */
    expected_triage_classification?: string;
    /**
     * Guidance on the expected fix
     */
    expected_remediation_approach?: string;
    /**
     * CVSS base score
     */
    cvss_score?: number;
    /**
     * Associated CVE identifier
     */
    cve_id?: (string | null);
    /**
     * Searchable tags
     */
    tags?: Array<string>;
};

