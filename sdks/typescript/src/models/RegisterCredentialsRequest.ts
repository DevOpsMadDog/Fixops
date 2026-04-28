/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for registering cloud credentials.
 */
export type RegisterCredentialsRequest = {
    /**
     * Cloud provider: aws | azure | gcp
     */
    provider: string;
    /**
     * AWS account ID / Azure subscription / GCP project
     */
    account_id: string;
    /**
     * Human-readable label
     */
    label?: string;
    /**
     * AWS access key ID
     */
    aws_access_key_id?: (string | null);
    /**
     * AWS secret access key
     */
    aws_secret_access_key?: (string | null);
    /**
     * AWS IAM role ARN for assume-role
     */
    aws_role_arn?: (string | null);
    /**
     * AWS region
     */
    aws_region?: string;
    /**
     * AWS temporary session token
     */
    aws_session_token?: (string | null);
    /**
     * Azure AD tenant ID
     */
    azure_tenant_id?: (string | null);
    /**
     * Azure service principal client ID
     */
    azure_client_id?: (string | null);
    /**
     * Azure service principal secret
     */
    azure_client_secret?: (string | null);
    /**
     * Azure subscription ID
     */
    azure_subscription_id?: (string | null);
    /**
     * GCP service account JSON (raw string)
     */
    gcp_service_account_json?: (string | null);
    /**
     * GCP project ID
     */
    gcp_project_id?: (string | null);
};

