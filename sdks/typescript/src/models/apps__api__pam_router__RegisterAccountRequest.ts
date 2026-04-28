/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__pam_router__RegisterAccountRequest = {
    username: string;
    /**
     * One of: service, admin, root, sa, shared, emergency
     */
    account_type?: string;
    system?: string;
    department?: string;
    owner?: string;
    is_vaulted?: boolean;
    rotation_days?: number;
    last_rotated?: (string | null);
    risk_score?: number;
    status?: string;
};

