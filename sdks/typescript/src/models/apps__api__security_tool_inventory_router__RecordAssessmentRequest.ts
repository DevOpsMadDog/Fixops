/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_tool_inventory_router__RecordAssessmentRequest = {
    /**
     * Tool being assessed
     */
    tool_id: string;
    /**
     * Assessor
     */
    assessed_by?: (string | null);
    /**
     * 0-100
     */
    coverage_score?: (number | null);
    /**
     * 0-100
     */
    effectiveness_score?: (number | null);
    /**
     * 0-100
     */
    utilization_pct?: (number | null);
    /**
     * Assessment findings
     */
    findings?: (string | null);
    /**
     * ISO assessment timestamp
     */
    assessed_at?: (string | null);
};

