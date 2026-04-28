/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_intel_platform_router__ReportCreate = {
    report_name: string;
    report_type?: string;
    classification?: string;
    tlp_level?: string;
    summary?: string;
    ioc_count?: number;
    threat_actors?: Array<string>;
    affected_sectors?: Array<string>;
    source_ids?: Array<string>;
    published_date?: (string | null);
};

