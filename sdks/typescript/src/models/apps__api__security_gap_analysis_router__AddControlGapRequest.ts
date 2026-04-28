/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_gap_analysis_router__AddControlGapRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Control identifier
     */
    control_id: string;
    /**
     * Control name
     */
    control_name: string;
    /**
     * Domain/category
     */
    domain?: string;
    /**
     * Requirement text
     */
    requirement?: string;
    /**
     * Current implementation state
     */
    current_state?: string;
    /**
     * Gap description
     */
    gap_description?: string;
    /**
     * critical|high|medium|low
     */
    risk_impact?: string;
    /**
     * low|medium|high|very-high
     */
    effort?: string;
    /**
     * critical|high|medium|low
     */
    priority?: string;
    /**
     * Gap owner
     */
    owner?: string;
    /**
     * Due date (ISO)
     */
    due_date?: string;
};

