/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PackageInput } from './PackageInput';
export type AnalyzePackagesRequest = {
    packages: Array<PackageInput>;
    typosquat_threshold?: number;
    min_age_days?: number;
    min_downloads?: number;
};

