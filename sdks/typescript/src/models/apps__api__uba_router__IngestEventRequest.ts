/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__uba_router__IngestEventRequest = {
    org_id: string;
    user_id: string;
    /**
     * login | file_access | email_send | data_download | usb_use | vpn_login | after_hours_access | privilege_use | failed_login
     */
    event_type: string;
    /**
     * Source IP address
     */
    source_ip?: string;
    /**
     * Device identifier or hostname
     */
    device?: string;
    /**
     * ISO-8601 event timestamp
     */
    timestamp?: (string | null);
    /**
     * Bytes transferred (for download events)
     */
    bytes_transferred?: number;
    /**
     * Whether this event was flagged anomalous
     */
    is_anomalous?: boolean;
};

