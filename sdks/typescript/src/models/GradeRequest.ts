/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to grade a drill's team response.
 *
 * Override fields allow manual override of auto-computed timings
 * (e.g. when detection was reported verbally before the system was updated).
 */
export type GradeRequest = {
    /**
     * Override auto-computed detection time (minutes from injection)
     */
    override_detection_minutes?: (number | null);
    /**
     * Override auto-computed remediation time (minutes from injection)
     */
    override_remediation_minutes?: (number | null);
};

