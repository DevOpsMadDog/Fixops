/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { NodeType } from './NodeType';
export type GraphNode = {
    id?: string;
    type: NodeType;
    name: string;
    provider?: string;
    region?: string;
    config?: Record<string, any>;
    risk_score?: number;
    vulnerabilities?: Array<string>;
    public?: boolean;
};

