/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ComplianceCert } from './ComplianceCert';
/**
 * A compliance certification with validity dates.
 */
export type CertificationRecord = {
    cert: ComplianceCert;
    /**
     * ISO-8601 date certification issued
     */
    issued_date: string;
    /**
     * ISO-8601 date certification expires
     */
    expiry_date: string;
    /**
     * Auditor or certification body
     */
    issuing_body?: (string | null);
    /**
     * Link to certification report
     */
    report_url?: (string | null);
};

