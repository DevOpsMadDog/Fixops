/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for POST /api/v1/hooks/uninstall.
 *
 * At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
 * supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.
 */
export type HookUninstallRequest = {
    /**
     * Specific hook policy record id (returned by /hooks-yaml/apply).
     */
    hook_id?: (string | null);
    /**
     * SHA-256 (or other content) hash of the policy to remove.
     */
    policy_hash?: (string | null);
    /**
     * Org/tenant id. Required if not supplied via X-Org-ID header.
     */
    org_id?: (string | null);
    /**
     * Audit reason recorded with the tombstone.
     */
    reason?: (string | null);
};

