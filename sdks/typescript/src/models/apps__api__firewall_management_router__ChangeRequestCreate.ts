/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__firewall_management_router__ChangeRequestCreate = {
    firewall_id: string;
    change_type?: string;
    requester?: string;
    business_justification?: string;
    rules_json?: Array<Record<string, any>>;
    expiry_date?: (string | null);
    risk_assessment?: string;
};

