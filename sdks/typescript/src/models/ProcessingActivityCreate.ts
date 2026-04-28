/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ProcessingActivityCreate = {
    activity_name: string;
    purpose?: string;
    legal_basis?: string;
    data_categories?: Array<string>;
    data_subjects?: Array<string>;
    retention_period_days?: number;
    third_party_recipients?: Array<string>;
    international_transfers?: Array<string>;
    dpiad_required?: boolean;
};

