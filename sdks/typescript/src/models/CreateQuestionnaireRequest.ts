/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateQuestionnaireRequest = {
    /**
     * Questionnaire display name
     */
    name: string;
    /**
     * Target vendor / recipient name
     */
    vendor_name: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * One of: soc2, vendor_assessment, sig_lite
     */
    template_type?: (string | null);
    /**
     * Custom questions list: [{text: str, category: str}]
     */
    custom_questions?: null;
};

