/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PerBuRiskRequest = {
    /**
     * Business unit ID
     */
    bu_id: string;
    /**
     * Optional list of findings. If omitted, pulled from security_findings by BU tag.
     */
    findings?: null;
};

