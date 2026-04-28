/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__compliance_gap_router__AddControlGapRequest = {
    /**
     * Parent assessment ID
     */
    assessment_id: string;
    /**
     * Framework control identifier
     */
    control_id: string;
    /**
     * Human-readable control name
     */
    control_name: string;
    /**
     * Control domain/category
     */
    domain?: string;
    /**
     * critical|high|medium|low
     */
    severity: string;
    /**
     * Description of the gap
     */
    gap_description?: string;
    /**
     * Current implementation state
     */
    current_state?: string;
    /**
     * Required implementation state
     */
    required_state?: string;
    /**
     * Estimated remediation hours
     */
    remediation_effort?: number;
};

