/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__nac_router__PolicyCreateReq = {
    org_id: string;
    name: string;
    device_types?: Array<string>;
    required_checks?: Array<string>;
    vlan_on_pass?: (string | null);
    vlan_on_fail?: (string | null);
    action_on_fail?: string;
};

