/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntSeverity } from './HuntSeverity';
import type { IOCType } from './IOCType';
/**
 * An Indicator of Compromise.
 */
export type IOC = {
    id?: string;
    type: IOCType;
    value: string;
    description?: string;
    confidence?: number;
    severity?: HuntSeverity;
    source?: string;
    tags?: Array<string>;
    stix_id?: (string | null);
    first_seen?: string;
    last_seen?: string;
    active?: boolean;
};

