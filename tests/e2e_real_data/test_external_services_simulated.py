"""
Simulate External Service Inputs Based on API Documentation

This module simulates responses from external services by researching their
API documentation online. This allows comprehensive testing without actual credentials.

Services simulated:
- Jira API (Atlassian)
- Confluence API (Atlassian)
- Slack API
- OpenAI GPT API
- Anthropic Claude API
- Google Gemini API
- AWS services (S3, Lambda, CloudWatch)
- Azure services (Key Vault, Storage)
- GCP services (Cloud Storage, Functions)
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExternalServiceSimulator:
    """Simulate external service responses based on their API documentation."""

    def __init__(self):
        self.fixtures_dir = Path(__file__).parent / "simulated_responses"
        self.fixtures_dir.mkdir(exist_ok=True)

    def simulate_jira_create_issue_response(self) -> Dict[str, Any]:
        """
        Simulate Jira API create issue response.
        Based on: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post
        """
        response = {
            "id": "10000",
            "key": "SEC-123",
            "self": "https://jira.example.com/rest/api/3/issue/10000",
            "transition": {
                "status": 200,
                "errorCollection": {"errorMessages": [], "errors": {}},
            },
        }

        fixture_file = self.fixtures_dir / "jira_create_issue.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Jira create issue simulation: {fixture_file}")

        return response

    def simulate_confluence_create_page_response(self) -> Dict[str, Any]:
        """
        Simulate Confluence API create page response.
        Based on: https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content/#api-wiki-rest-api-content-post
        """
        response = {
            "id": "123456",
            "type": "page",
            "status": "current",
            "title": "FixOps Security Analysis Report",
            "space": {"key": "SECOPS", "name": "Security Operations"},
            "version": {"number": 1, "when": "2025-11-01T14:00:00.000Z"},
            "_links": {
                "webui": "/spaces/SECOPS/pages/123456/FixOps+Security+Analysis+Report",
                "self": "https://confluence.example.com/rest/api/content/123456",
            },
        }

        fixture_file = self.fixtures_dir / "confluence_create_page.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Confluence create page simulation: {fixture_file}")

        return response

    def simulate_slack_post_message_response(self) -> Dict[str, Any]:
        """
        Simulate Slack API post message response.
        Based on: https://api.slack.com/methods/chat.postMessage
        """
        response = {
            "ok": True,
            "channel": "C1234567890",
            "ts": "1635789600.123456",
            "message": {
                "type": "message",
                "subtype": None,
                "text": "FixOps Alert: High severity vulnerability detected",
                "ts": "1635789600.123456",
                "username": "FixOps Bot",
                "bot_id": "B1234567890",
            },
        }

        fixture_file = self.fixtures_dir / "slack_post_message.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Slack post message simulation: {fixture_file}")

        return response

    def simulate_openai_chat_completion_response(self) -> Dict[str, Any]:
        """
        Simulate OpenAI GPT API chat completion response.
        Based on: https://platform.openai.com/docs/api-reference/chat/create
        """
        response = {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "verdict": "block",
                                "confidence": 0.95,
                                "reasoning": "This CVE is actively exploited (KEV listed) and affects a mission-critical service with PII data exposure. MITRE ATT&CK: T1190 (Exploit Public-Facing Application). Immediate remediation required.",
                                "mitre_techniques": ["T1190", "T1133"],
                                "compliance_impact": [
                                    "SOC2 CC7.2",
                                    "PCI-DSS 6.2",
                                    "GDPR Article 32",
                                ],
                            }
                        ),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 100,
                "total_tokens": 250,
            },
        }

        fixture_file = self.fixtures_dir / "openai_chat_completion.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created OpenAI chat completion simulation: {fixture_file}")

        return response

    def simulate_anthropic_message_response(self) -> Dict[str, Any]:
        """
        Simulate Anthropic Claude API message response.
        Based on: https://docs.anthropic.com/claude/reference/messages_post
        """
        response = {
            "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "verdict": "block",
                            "confidence": 0.92,
                            "reasoning": "High severity SQL injection vulnerability in production payment service. CWE-89 maps to PCI-DSS 6.5.1 requirement. Exploit code publicly available.",
                            "compliance_gaps": ["PCI-DSS 6.5.1", "ISO27001 A.14.2.8"],
                        }
                    ),
                }
            ],
            "model": "claude-3-opus-20240229",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 120, "output_tokens": 80},
        }

        fixture_file = self.fixtures_dir / "anthropic_message.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Anthropic message simulation: {fixture_file}")

        return response

    def simulate_google_gemini_response(self) -> Dict[str, Any]:
        """
        Simulate Google Gemini API response.
        Based on: https://ai.google.dev/api/rest/v1/models/generateContent
        """
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "verdict": "review",
                                        "confidence": 0.78,
                                        "reasoning": "CSRF vulnerability detected but service has partner-only exposure. Medium severity with compensating controls possible.",
                                        "recommended_actions": [
                                            "Implement CSRF tokens",
                                            "Add SameSite cookie attributes",
                                            "Review session management",
                                        ],
                                    }
                                )
                            }
                        ],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                    "index": 0,
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 90,
                "totalTokenCount": 190,
            },
        }

        fixture_file = self.fixtures_dir / "google_gemini.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Google Gemini simulation: {fixture_file}")

        return response

    def simulate_aws_s3_put_object_response(self) -> Dict[str, Any]:
        """
        Simulate AWS S3 PutObject response.
        Based on: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
        """
        response = {
            "ETag": '"d41d8cd98f00b204e9800998ecf8427e"',
            "ServerSideEncryption": "AES256",
            "VersionId": "3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo",
            "ResponseMetadata": {
                "RequestId": "1234567890ABCDEF",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amz-id-2": "abcdef123456",
                    "x-amz-request-id": "1234567890ABCDEF",
                    "date": "Fri, 01 Nov 2025 14:00:00 GMT",
                    "etag": '"d41d8cd98f00b204e9800998ecf8427e"',
                    "server": "AmazonS3",
                },
            },
        }

        fixture_file = self.fixtures_dir / "aws_s3_put_object.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created AWS S3 PutObject simulation: {fixture_file}")

        return response

    def simulate_azure_keyvault_get_secret_response(self) -> Dict[str, Any]:
        """
        Simulate Azure Key Vault get secret response.
        Based on: https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret
        """
        response = {
            "value": "encrypted-evidence-key-12345",
            "id": "https://fixops-kv.vault.azure.net/secrets/evidence-encryption-key/abc123",
            "attributes": {
                "enabled": True,
                "created": 1635789600,
                "updated": 1635789600,
                "recoveryLevel": "Recoverable+Purgeable",
            },
            "contentType": "application/octet-stream",
        }

        fixture_file = self.fixtures_dir / "azure_keyvault_get_secret.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created Azure Key Vault get secret simulation: {fixture_file}")

        return response

    def simulate_gcp_storage_upload_response(self) -> Dict[str, Any]:
        """
        Simulate GCP Cloud Storage upload response.
        Based on: https://cloud.google.com/storage/docs/json_api/v1/objects/insert
        """
        response = {
            "kind": "storage#object",
            "id": "fixops-evidence/evidence-bundle-123.tar.gz/1635789600000000",
            "selfLink": "https://www.googleapis.com/storage/v1/b/fixops-evidence/o/evidence-bundle-123.tar.gz",
            "name": "evidence-bundle-123.tar.gz",
            "bucket": "fixops-evidence",
            "generation": "1635789600000000",
            "metageneration": "1",
            "contentType": "application/gzip",
            "timeCreated": "2025-11-01T14:00:00.000Z",
            "updated": "2025-11-01T14:00:00.000Z",
            "storageClass": "STANDARD",
            "size": "1048576",
            "md5Hash": "rL0Y20zC+Fzt72VPzMSk2A==",
            "crc32c": "AAAAAA==",
        }

        fixture_file = self.fixtures_dir / "gcp_storage_upload.json"
        fixture_file.write_text(json.dumps(response, indent=2))
        logger.info(f"Created GCP Storage upload simulation: {fixture_file}")

        return response

    def create_all_simulations(self):
        """Create all simulated external service responses."""
        logger.info("Creating all external service simulations...")

        self.simulate_jira_create_issue_response()
        self.simulate_confluence_create_page_response()
        self.simulate_slack_post_message_response()
        self.simulate_openai_chat_completion_response()
        self.simulate_anthropic_message_response()
        self.simulate_google_gemini_response()
        self.simulate_aws_s3_put_object_response()
        self.simulate_azure_keyvault_get_secret_response()
        self.simulate_gcp_storage_upload_response()

        logger.info(f"All simulations created in: {self.fixtures_dir}")


def main():
    """Generate all simulated external service responses."""
    simulator = ExternalServiceSimulator()
    simulator.create_all_simulations()


if __name__ == "__main__":
    main()
