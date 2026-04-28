/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ContributionProgram } from './ContributionProgram';
/**
 * Response for CVE contribution submission.
 */
export type ContributeResponse = {
    submission_id: string;
    vuln_id: string;
    program: ContributionProgram;
    status: string;
    cve_id?: (string | null);
    estimated_assignment_date?: (string | null);
    tracking_url?: (string | null);
};

