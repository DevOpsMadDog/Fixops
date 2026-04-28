/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__soc_triage_router__IngestAlertRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * siem | edr | ndr | xdr | manual
     */
    alert_source?: string;
    /**
     * Short type label e.g. 'brute_force'
     */
    alert_type?: string;
    /**
     * Alert title — used for ML keyword scoring
     */
    title: string;
    /**
     * Full alert body / raw log
     */
    raw_description?: string;
    /**
     * critical | high | medium | low | info
     */
    severity_original?: string;
    /**
     * Analyst who ingested the alert (optional)
     */
    analyst_id?: string;
};

