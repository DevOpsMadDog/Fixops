/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ServiceInfo } from './ServiceInfo';
export type AttackSurfaceSnapshot = {
    id?: string;
    target: string;
    timestamp?: string;
    open_ports?: Array<number>;
    services?: Array<ServiceInfo>;
    endpoints?: Array<string>;
    deps?: Array<string>;
    secrets_exposed?: Array<string>;
    score?: number;
    metadata?: Record<string, any>;
};

