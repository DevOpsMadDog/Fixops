/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CoreStats } from './CoreStats';
/**
 * Knowledge Core information.
 */
export type CoreResponse = {
    core_id: number;
    name: string;
    description: string;
    entity_types: Array<string>;
    stats: CoreStats;
};

