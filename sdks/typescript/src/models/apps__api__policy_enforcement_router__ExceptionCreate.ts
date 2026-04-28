/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__policy_enforcement_router__ExceptionCreate = {
    policy_id: string;
    /**
     * permanent/temporary/conditional
     */
    exception_type?: string;
    justification: string;
    requested_by: string;
    approver?: (string | null);
    expiry_date?: (string | null);
};

