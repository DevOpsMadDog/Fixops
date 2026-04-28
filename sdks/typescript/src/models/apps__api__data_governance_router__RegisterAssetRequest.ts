/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__data_governance_router__RegisterAssetRequest = {
    name: string;
    description?: string;
    asset_type?: string;
    classification?: string;
    owner?: string;
    data_categories?: Array<string>;
    retention_days?: number;
    location?: string;
    encrypted?: boolean;
    last_audited?: (string | null);
};

