/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_abuse_detection_router__RecordIncidentRequest = {
    endpoint_id: string;
    abuse_type: string;
    severity: string;
    source_ip?: (string | null);
    request_count?: number;
    time_window_seconds?: number;
    blocked?: boolean;
    status?: string;
    detected_at?: (string | null);
};

