/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpgradePlanResult = {
    generated_at: string;
    total_vulnerabilities: number;
    critical: Array<Record<string, string>>;
    high: Array<Record<string, string>>;
    medium: Array<Record<string, string>>;
    low: Array<Record<string, string>>;
    upgrade_commands: Array<string>;
    summary: string;
};

