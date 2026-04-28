/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__endpoint_compliance_router__BaselineCreate = {
    baseline_name: string;
    /**
     * windows/linux/macos/android/ios
     */
    os_type?: string;
    /**
     * CIS benchmark identifier
     */
    benchmark?: string;
    required_checks?: Array<string>;
    target_score?: number;
};

