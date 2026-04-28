/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__casb_router__RecordActivityRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Cloud application name
     */
    app_name: string;
    /**
     * User identifier (email or username)
     */
    user: string;
    /**
     * Activity type: upload/download/share/delete
     */
    activity_type: string;
    /**
     * File MIME type or extension
     */
    file_type?: string;
    /**
     * Size of data transferred in bytes
     */
    size_bytes?: number;
    /**
     * Destination: internal/external/public
     */
    destination?: string;
    /**
     * Data classification: public/internal/confidential/secret
     */
    data_classification?: string;
};

