/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__siem_connector_router__IngestRequest = {
    /**
     * Tenant identifier
     */
    org_id?: string;
    /**
     * Raw SIEM payload (str, dict, or list)
     */
    payload: any;
    /**
     * Adapter key — one of: splunk_hec | datadog | sentinel_kql | elk_bulk | wazuh_alert | suricata_eve | cef | syslog | json_lines | auto
     */
    format?: string;
    /**
     * Optional SIEM source ID
     */
    source_id?: (string | null);
};

