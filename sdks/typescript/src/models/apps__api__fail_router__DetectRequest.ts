/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to mark a drill finding as detected.
 */
export type apps__api__fail_router__DetectRequest = {
    /**
     * Who detected the finding
     */
    detected_by?: (string | null);
    /**
     * Notes about the detection
     */
    detection_note?: string;
};

