/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddFirewallRuleRequest } from '../models/AddFirewallRuleRequest';
import type { AnalyseDNSRequest } from '../models/AnalyseDNSRequest';
import type { apps__api__network_security_router__RegisterAssetRequest } from '../models/apps__api__network_security_router__RegisterAssetRequest';
import type { apps__api__network_security_router__RegisterCertificateRequest } from '../models/apps__api__network_security_router__RegisterCertificateRequest';
import type { DNSThreat } from '../models/DNSThreat';
import type { FirewallRule } from '../models/FirewallRule';
import type { FirewallRuleAuditResult } from '../models/FirewallRuleAuditResult';
import type { FlowAnomaly } from '../models/FlowAnomaly';
import type { NDRSummary } from '../models/NDRSummary';
import type { NetworkAsset } from '../models/NetworkAsset';
import type { ReportDNSRebindingRequest } from '../models/ReportDNSRebindingRequest';
import type { SegmentationFinding } from '../models/SegmentationFinding';
import type { TLSCertificate } from '../models/TLSCertificate';
import type { TLSIssue } from '../models/TLSIssue';
import type { ZeroTrustScore } from '../models/ZeroTrustScore';
import type { ZeroTrustScoreRequest } from '../models/ZeroTrustScoreRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class NetworkSecurityService {
    /**
     * Register a network asset
     * Register or update a network asset (subnet, VLAN, gateway, DNS server, etc.).
     *
     * Assets are upserted by ID. To update a known asset, include its ID in the request body.
     * @param requestBody
     * @returns NetworkAsset Successful Response
     * @throws ApiError
     */
    public static registerAssetApiV1NetworkAssetsPost(
        requestBody: apps__api__network_security_router__RegisterAssetRequest,
    ): CancelablePromise<NetworkAsset> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/assets',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List network assets
     * List all registered network assets, optionally filtered by type.
     * @param orgId Organisation ID
     * @param assetType Filter by asset type
     * @returns NetworkAsset Successful Response
     * @throws ApiError
     */
    public static listAssetsApiV1NetworkAssetsGet(
        orgId: string = 'default',
        assetType?: (string | null),
    ): CancelablePromise<Array<NetworkAsset>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/assets',
            query: {
                'org_id': orgId,
                'asset_type': assetType,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Network topology map
     * Build and return a topology map from registered assets.
     *
     * Returns assets grouped by VLAN or asset type, with total asset count.
     * @param orgId Organisation ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static networkTopologyApiV1NetworkTopologyGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/topology',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Run segmentation analysis
     * Analyse registered assets for segmentation violations.
     *
     * Checks PCI CDE isolation, HIPAA ePHI separation, DMZ configuration,
     * and flat network detection. Findings are persisted and returned.
     * @param orgId Organisation ID
     * @returns SegmentationFinding Successful Response
     * @throws ApiError
     */
    public static runSegmentationScanApiV1NetworkSegmentationScanPost(
        orgId: string = 'default',
    ): CancelablePromise<Array<SegmentationFinding>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/segmentation/scan',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List segmentation findings
     * Retrieve all persisted segmentation findings for the org.
     * @param orgId Organisation ID
     * @returns SegmentationFinding Successful Response
     * @throws ApiError
     */
    public static listSegmentationFindingsApiV1NetworkSegmentationGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<SegmentationFinding>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/segmentation',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add a firewall rule
     * Register a firewall rule for audit analysis.
     * @param requestBody
     * @returns FirewallRule Successful Response
     * @throws ApiError
     */
    public static addFirewallRuleApiV1NetworkFirewallRulesPost(
        requestBody: AddFirewallRuleRequest,
    ): CancelablePromise<FirewallRule> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/firewall/rules',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Audit firewall rules
     * Audit all registered firewall rules for:
     * - Overly permissive (any-any-any allow)
     * - Shadowed rules (never evaluated)
     * - Expired temporary rules
     * - Unnecessary bidirectional access
     * @param orgId Organisation ID
     * @returns FirewallRuleAuditResult Successful Response
     * @throws ApiError
     */
    public static auditFirewallRulesApiV1NetworkFirewallAuditPost(
        orgId: string = 'default',
    ): CancelablePromise<Array<FirewallRuleAuditResult>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/firewall/audit',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Analyse a DNS query for threats
     * Analyse a DNS domain for tunneling, DGA, and unauthorized resolver threats.
     *
     * Returns a list of detected threats (empty list if none found).
     * @param requestBody
     * @returns DNSThreat Successful Response
     * @throws ApiError
     */
    public static analyseDnsApiV1NetworkDnsAnalysePost(
        requestBody: AnalyseDNSRequest,
    ): CancelablePromise<Array<DNSThreat>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/dns/analyse',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Report a DNS rebinding attempt
     * Report a DNS rebinding event: a public domain resolved to a private IP.
     *
     * Returns the threat record if the resolved IP is private, null otherwise.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static reportDnsRebindingApiV1NetworkDnsRebindingPost(
        requestBody: ReportDNSRebindingRequest,
    ): CancelablePromise<(DNSThreat | null)> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/dns/rebinding',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List DNS threats
     * Retrieve all persisted DNS threat records for the org.
     * @param orgId Organisation ID
     * @returns DNSThreat Successful Response
     * @throws ApiError
     */
    public static listDnsThreatsApiV1NetworkDnsThreatsGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<DNSThreat>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/dns/threats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Register a TLS certificate
     * Register a TLS certificate observed in the environment.
     *
     * Issues (expiry, weak ciphers, deprecated protocols, missing CT) are
     * automatically detected and persisted.
     * @param requestBody
     * @returns TLSCertificate Successful Response
     * @throws ApiError
     */
    public static registerCertificateApiV1NetworkTlsCertificatesPost(
        requestBody: apps__api__network_security_router__RegisterCertificateRequest,
    ): CancelablePromise<TLSCertificate> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/tls/certificates',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List TLS certificates
     * Return all registered TLS certificates for the org.
     * @param orgId Organisation ID
     * @returns TLSCertificate Successful Response
     * @throws ApiError
     */
    public static listCertificatesApiV1NetworkTlsCertificatesGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<TLSCertificate>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/tls/certificates',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List TLS issues
     * Return all detected TLS/SSL issues for the org.
     * @param orgId Organisation ID
     * @returns TLSIssue Successful Response
     * @throws ApiError
     */
    public static listTlsIssuesApiV1NetworkTlsIssuesGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<TLSIssue>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/tls/issues',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Analyse network flows for anomalies
     * Analyse network flows recorded in the look-back window for:
     * - Unusual traffic volume (> 3x baseline for a src/dst pair)
     * - Beaconing (regular periodic connections)
     * - Lateral movement (host connecting to many internal targets)
     * - Data exfiltration (large internal-to-external transfer)
     * @param orgId Organisation ID
     * @param windowHours Look-back window in hours
     * @returns FlowAnomaly Successful Response
     * @throws ApiError
     */
    public static analyseFlowsApiV1NetworkFlowsAnalysePost(
        orgId: string = 'default',
        windowHours: number = 24,
    ): CancelablePromise<Array<FlowAnomaly>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/flows/analyse',
            query: {
                'org_id': orgId,
                'window_hours': windowHours,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List flow anomalies
     * Return all persisted network flow anomalies for the org.
     * @param orgId Organisation ID
     * @returns FlowAnomaly Successful Response
     * @throws ApiError
     */
    public static listFlowAnomaliesApiV1NetworkFlowsAnomaliesGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<FlowAnomaly>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/flows/anomalies',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Compute Zero Trust score for a segment
     * Score Zero Trust implementation for a network segment across five dimensions:
     * Device Posture, User Identity, Network Context, Application, and Data.
     *
     * Returns an overall score (0–100) with letter grade and per-dimension breakdown.
     * @param requestBody
     * @returns ZeroTrustScore Successful Response
     * @throws ApiError
     */
    public static computeZeroTrustScoreApiV1NetworkZerotrustScorePost(
        requestBody: ZeroTrustScoreRequest,
    ): CancelablePromise<ZeroTrustScore> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/zerotrust/score',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Zero Trust scores
     * Return all computed Zero Trust scores for the org, newest first.
     * @param orgId Organisation ID
     * @returns ZeroTrustScore Successful Response
     * @throws ApiError
     */
    public static listZeroTrustScoresApiV1NetworkZerotrustScoresGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<ZeroTrustScore>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/zerotrust/scores',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * NDR health summary
     * Return a high-level NDR health summary:
     * asset count, segmentation violations, firewall issue count, DNS threats,
     * TLS issues, flow anomalies, and latest Zero Trust score.
     * @param orgId Organisation ID
     * @returns NDRSummary Successful Response
     * @throws ApiError
     */
    public static ndrSummaryApiV1NetworkSummaryGet(
        orgId: string = 'default',
    ): CancelablePromise<NDRSummary> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/summary',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
