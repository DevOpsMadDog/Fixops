/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EdgeType } from './EdgeType';
export type GraphEdge = {
    id?: string;
    source_id: string;
    target_id: string;
    type: EdgeType;
    metadata?: Record<string, any>;
};

