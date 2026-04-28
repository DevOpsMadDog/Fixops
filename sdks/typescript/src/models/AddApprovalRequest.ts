/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApprovalDecision } from './ApprovalDecision';
export type AddApprovalRequest = {
    approver_id: string;
    approver_name: string;
    approver_role: string;
    decision: ApprovalDecision;
    comments?: (string | null);
    conditions?: Array<string>;
};

