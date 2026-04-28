/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IOC } from './IOC';
/**
 * Body for bulk IOC import. Accepts either a STIX 2.1 bundle or a plain list.
 */
export type ImportIOCsRequest = {
    /**
     * STIX 2.1 bundle with indicator objects
     */
    stix_bundle?: (Record<string, any> | null);
    /**
     * Plain list of IOC objects for direct import
     */
    iocs?: (Array<IOC> | null);
};

