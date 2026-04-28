/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__data_exfiltration_router__RecordIncidentRequest = {
    incident_type: string;
    severity?: string;
    user_id?: string;
    data_classification?: string;
    estimated_volume_mb?: number;
    destination?: string;
    detection_method?: string;
    status?: string;
    blocked?: boolean;
    detected_at?: (string | null);
};

