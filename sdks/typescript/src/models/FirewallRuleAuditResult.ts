/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__network_security__Severity } from './core__network_security__Severity';
import type { FirewallRuleIssue } from './FirewallRuleIssue';
export type FirewallRuleAuditResult = {
    rule_id: string;
    rule_name: string;
    issue: FirewallRuleIssue;
    severity: core__network_security__Severity;
    description: string;
    recommendation: string;
};

