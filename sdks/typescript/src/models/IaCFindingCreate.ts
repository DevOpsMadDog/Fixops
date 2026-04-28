/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IaCProvider } from './IaCProvider';
/**
 * Request model for creating IaC finding.
 */
export type IaCFindingCreate = {
    provider: IaCProvider;
    severity: string;
    title: string;
    description: string;
    file_path: string;
    line_number: number;
    resource_type: string;
    resource_name: string;
    rule_id: string;
    remediation?: (string | null);
    metadata?: Record<string, any>;
};

