/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CVERef } from './CVERef';
export type SBOMPackageEntry = {
    name: string;
    ecosystem?: string;
    version?: string;
    is_direct?: boolean;
    license_ok?: boolean;
    cve_ids?: Array<CVERef>;
};

