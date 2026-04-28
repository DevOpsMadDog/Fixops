/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Drill score response.
 */
export type GradeResponse = {
    drill_id: string;
    detection_speed: number;
    triage_accuracy: number;
    remediation_speed: number;
    communication: number;
    overall: number;
    grade: string;
    detection_minutes_actual?: (number | null);
    detection_minutes_target?: (number | null);
    triage_classification_actual?: (string | null);
    triage_classification_expected?: (string | null);
    remediation_minutes_actual?: (number | null);
    escalated_correctly: boolean;
    team_notified: boolean;
    feedback: Array<string>;
};

