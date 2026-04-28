/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RuleResponse = {
    id: string;
    name: string;
    trigger_condition: Record<string, any>;
    action: string;
    config: Record<string, any>;
    enabled: boolean;
    execution_count: number;
    last_triggered: (string | null);
    org_id: string;
};

