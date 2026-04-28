/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DetectionCreate = {
    org_id: string;
    detection_name: string;
    detection_type?: string;
    affected_systems?: Array<string>;
    file_extensions?: Array<string>;
    confidence?: number;
    severity?: string;
};

