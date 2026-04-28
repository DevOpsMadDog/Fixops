/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { OWASPCategory } from './OWASPCategory';
export type ProgramScope = {
    /**
     * In-scope assets (domains, IPs, repos)
     */
    in_scope?: Array<string>;
    /**
     * Explicitly out-of-scope assets
     */
    out_of_scope?: Array<string>;
    /**
     * Accepted vulnerability categories
     */
    vulnerability_types?: Array<OWASPCategory>;
};

