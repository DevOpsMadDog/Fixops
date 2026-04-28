/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DetectionCreateReq = {
    org_id: string;
    package_id: string;
    detection_type: string;
    confidence_score?: number;
    evidence?: (string | null);
    severity?: string;
    detected_at?: (string | null);
};

