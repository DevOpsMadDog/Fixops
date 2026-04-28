/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IPRuleAction } from './IPRuleAction';
export type AddIPRuleRequest = {
    /**
     * IP address or CIDR block, e.g. '10.0.0.0/8' or '1.2.3.4'
     */
    cidr: string;
    /**
     * 'allow' or 'block'
     */
    action: IPRuleAction;
    /**
     * Human-readable description
     */
    description?: string;
    /**
     * Who created this rule
     */
    created_by?: string;
};

