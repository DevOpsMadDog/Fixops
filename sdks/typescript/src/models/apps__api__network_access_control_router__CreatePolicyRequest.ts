/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_access_control_router__CreatePolicyRequest = {
    org_id?: string;
    /**
     * Policy name
     */
    name: string;
    required_posture_score?: number;
    /**
     * allow/restrict/quarantine/block
     */
    action?: string;
    /**
     * all/workstation/laptop/server/mobile/iot
     */
    applies_to?: string;
};

