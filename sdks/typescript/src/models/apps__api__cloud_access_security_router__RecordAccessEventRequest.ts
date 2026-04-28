/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_access_security_router__RecordAccessEventRequest = {
    org_id?: string;
    app_id: string;
    user_id?: string;
    access_type?: string;
    data_accessed?: string;
    bytes_transferred?: number;
    source_ip?: string;
    success?: boolean;
    occurred_at?: (string | null);
};

