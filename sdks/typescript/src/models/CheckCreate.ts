/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CheckCreate = {
    check_id: string;
    check_name?: string;
    /**
     * cis_windows_l1/cis_ubuntu/etc.
     */
    benchmark?: string;
    /**
     * account_policy/local_policy/etc.
     */
    category?: string;
    /**
     * critical/high/medium/low
     */
    severity?: string;
    /**
     * passed/failed/not_applicable/error
     */
    status?: string;
    actual_value?: string;
    expected_value?: string;
    remediation?: string;
    scanned_at?: (string | null);
};

