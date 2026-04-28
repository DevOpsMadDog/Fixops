/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__breach_response_router__CreateCaseRequest = {
    title: string;
    breach_type: string;
    data_types_affected?: Array<string>;
    estimated_records_affected?: number;
    notifiable?: boolean;
    discovered_at?: (string | null);
    breach_date?: (string | null);
    regulatory_deadline?: (string | null);
    status?: string;
    org_id?: string;
};

