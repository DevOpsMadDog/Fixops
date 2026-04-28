/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ControlStatus } from './ControlStatus';
/**
 * Request body for updating a control's implementation status.
 */
export type apps__api__fedramp_router__ControlStatusUpdate = {
    status: ControlStatus;
    implementation_notes?: string;
    evidence_ids?: (Array<string> | null);
};

