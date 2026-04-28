/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__privacy_impact_assessment_router__AssessmentCreate = {
    project_name: string;
    assessment_type?: string;
    data_controller?: string;
    data_processor?: string;
    legal_basis?: string;
    data_categories?: Array<string>;
    data_subjects?: Array<string>;
    retention_period_days?: number;
    cross_border_transfer?: boolean;
};

