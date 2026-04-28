/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__cspm_engine__CloudProvider } from './core__cspm_engine__CloudProvider';
export type api__cspm_router__TriggerScanRequest = {
    org_id?: string;
    account_ids?: Array<string>;
    providers?: Array<core__cspm_engine__CloudProvider>;
    rule_ids?: (Array<string> | null);
};

