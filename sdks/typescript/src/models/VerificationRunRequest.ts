/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DifferentialRequestModel } from './DifferentialRequestModel';
import type { ExploitPayloadModel } from './ExploitPayloadModel';
import type { ProductSignatureModel } from './ProductSignatureModel';
import type { VersionRangeModel } from './VersionRangeModel';
export type VerificationRunRequest = {
    org_id: string;
    target_url: string;
    signature: ProductSignatureModel;
    version_range?: (VersionRangeModel | null);
    exploit_payloads?: Array<ExploitPayloadModel>;
    differential_benign?: (DifferentialRequestModel | null);
    differential_malicious?: (DifferentialRequestModel | null);
    timeout?: number;
};

