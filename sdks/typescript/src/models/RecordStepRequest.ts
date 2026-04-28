/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordStepRequest = {
    /**
     * Step outcome: executed, detected, blocked, missed
     */
    outcome: string;
    /**
     * Was the step detected by ALDECI?
     */
    detected?: boolean;
    /**
     * Which ALDECI engine detected it: siem, edr, ndr, soar, threat_intel, anomaly, manual, none
     */
    detection_engine?: string;
    /**
     * Did an alert fire in the platform?
     */
    alert_fired?: boolean;
    /**
     * Seconds from attack execution to detection
     */
    time_to_detect_seconds?: (number | null);
    /**
     * Free-text detection notes
     */
    detection_notes?: string;
};

