/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__mobile_app_security_router__RegisterAppRequest = {
    app_name: string;
    bundle_id: string;
    platform: string;
    version?: string;
    category: string;
    risk_score?: number;
    risk_level?: string;
    status?: string;
    last_scanned?: (string | null);
};

