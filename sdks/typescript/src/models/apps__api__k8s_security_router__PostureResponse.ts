/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__k8s_security_router__PostureResponse = {
    cluster_name: string;
    overall_score: number;
    grade: string;
    total_checks: number;
    passed_checks: number;
    failed_checks: number;
    warned_checks: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    scanned_at: string;
    scan_duration_ms: number;
    namespace_scores: Array<Record<string, any>>;
    workload_scores: Array<Record<string, any>>;
};

