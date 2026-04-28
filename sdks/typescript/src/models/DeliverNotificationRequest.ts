/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to deliver a specific notification.
 *
 * Note: Credentials should be configured via environment variables for security:
 * - FIXOPS_SLACK_WEBHOOK_URL: Slack webhook URL
 * - FIXOPS_SMTP_PASSWORD: SMTP password
 * Do not pass credentials in request bodies.
 */
export type DeliverNotificationRequest = {
    email_smtp_host?: (string | null);
    email_smtp_port?: (number | null);
    email_smtp_user?: (string | null);
    email_from?: (string | null);
};

