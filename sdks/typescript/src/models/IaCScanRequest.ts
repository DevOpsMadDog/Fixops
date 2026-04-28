/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IaCScanRequest = {
    /**
     * Raw IaC template content (Terraform HCL or CloudFormation JSON)
     */
    template_text: string;
    /**
     * Template type: 'terraform', 'cloudformation', or 'auto' (detected by content)
     */
    template_type?: string;
    /**
     * Optional filename for context
     */
    filename?: string;
};

