/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RiskSignalSeverity } from './RiskSignalSeverity';
import type { RiskSignalType } from './RiskSignalType';
/**
 * Request body for recording a monitoring signal.
 */
export type RecordSignalRequest = {
    signal_type: RiskSignalType;
    severity: RiskSignalSeverity;
    title: string;
    description: string;
    source?: string;
    metadata?: Record<string, any>;
};

