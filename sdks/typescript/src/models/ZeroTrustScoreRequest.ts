/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ZeroTrustScoreRequest = {
    /**
     * Network segment name to score
     */
    segment: string;
    org_id?: string;
    /**
     * Device posture ratio 0–1
     */
    device_posture_score?: number;
    /**
     * All users authenticated via IdP
     */
    identity_verified?: boolean;
    /**
     * MFA enforced for all users
     */
    mfa_enabled?: boolean;
    /**
     * Micro-segmentation implemented
     */
    network_microsegmented?: boolean;
    /**
     * App-level least privilege enforced
     */
    app_least_privilege?: boolean;
    /**
     * Data classification implemented
     */
    data_classified?: boolean;
};

