/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__alert_triage_router__IngestAlertRequest = {
    /**
     * Short alert title
     */
    title: string;
    /**
     * siem | edr | ndr | cloud | waf | ids | firewall | custom
     */
    source_system?: string;
    /**
     * critical | high | medium | low | info
     */
    severity?: string;
    /**
     * Raw alert payload from source system
     */
    raw_alert_json?: (Record<string, any> | null);
};

