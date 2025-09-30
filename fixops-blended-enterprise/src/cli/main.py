#!/usr/bin/env python3
"""
FixOps Enterprise CLI - CI/CD Integration Tool
High-performance command-line interface for DevSecOps automation
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import argparse
import structlog
from datetime import datetime

# Add project root to path  
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.config.settings import get_settings
from src.db.session import DatabaseManager
from src.models.security_sqlite import SecurityFinding, Service, ScannerType, SeverityLevel
from src.services.correlation_engine import correlation_engine
from src.services.policy_engine import policy_engine, PolicyContext, PolicyDecision
from src.services.fix_engine import fix_engine
from src.services.cache_service import CacheService

logger = structlog.get_logger()
settings = get_settings()


class FixOpsCLI:
    """
    FixOps CLI for CI/CD pipeline integration
    Provides high-performance security scanning integration and policy automation
    """
    
    def __init__(self):
        self.start_time = time.perf_counter()
        
    async def initialize(self):
        """Initialize CLI components"""
        await DatabaseManager.initialize()
        await CacheService.initialize()
        logger.info("FixOps CLI initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        await DatabaseManager.close()
        await CacheService.close()
    
    async def ingest_scan_results(self, args) -> Dict[str, Any]:
        """
        Ingest security scan results from CI/CD pipeline
        High-performance bulk ingestion with deduplication
        """
        start_time = time.perf_counter()
        
        try:
            # Read scan results file
            scan_file = Path(args.scan_file)
            if not scan_file.exists():
                raise FileNotFoundError(f"Scan file not found: {scan_file}")
            
            with open(scan_file, 'r') as f:
                if args.format == 'sarif':
                    scan_data = await self._parse_sarif(f.read())
                elif args.format == 'json':
                    scan_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported format: {args.format}")
            
            # Get or create service
            service = await self._get_or_create_service(
                service_name=args.service_name,
                environment=args.environment,
                repository_url=args.repository_url
            )
            
            # Process findings in batches for performance
            findings = []
            batch_size = 100
            
            for i in range(0, len(scan_data.get('findings', [])), batch_size):
                batch = scan_data['findings'][i:i + batch_size]
                batch_findings = await self._process_findings_batch(
                    batch, service, args.scanner_type, args.scanner_name
                )
                findings.extend(batch_findings)
            
            # Run correlation and policy evaluation
            correlation_results = []
            policy_results = []
            
            if args.enable_correlation:
                finding_ids = [f.id for f in findings]
                correlation_results = await correlation_engine.batch_correlate_findings(finding_ids)
            
            if args.enable_policy_evaluation:
                policy_contexts = [
                    await self._create_policy_context(f, service) for f in findings
                ]
                policy_results = await policy_engine.batch_evaluate_policies(policy_contexts)
            
            # Generate summary
            total_time = time.perf_counter() - start_time
            
            result = {
                "status": "success",
                "service_id": service.id,
                "service_name": service.name,
                "findings_ingested": len(findings),
                "correlations_found": len(correlation_results),
                "policy_decisions": len(policy_results),
                "processing_time_ms": total_time * 1000,
                "performance_metrics": {
                    "ingestion_rate_per_sec": len(findings) / total_time,
                    "hot_path_compliant": total_time * 1_000_000 < settings.HOT_PATH_TARGET_LATENCY_US * len(findings)
                }
            }
            
            # Policy decision summary
            if policy_results:
                decision_counts = {}
                blocked_findings = []
                
                for i, policy_result in enumerate(policy_results):
                    decision = policy_result.decision.value
                    decision_counts[decision] = decision_counts.get(decision, 0) + 1
                    
                    if policy_result.decision == PolicyDecision.BLOCK:
                        blocked_findings.append({
                            "finding_id": findings[i].id,
                            "title": findings[i].title,
                            "severity": findings[i].severity,
                            "rationale": policy_result.rationale
                        })
                
                result["policy_summary"] = {
                    "decision_counts": decision_counts,
                    "blocked_findings": blocked_findings,
                    "deployment_blocked": any(pr.decision == PolicyDecision.BLOCK for pr in policy_results)
                }
            
            # Output results
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            # Set exit code based on policy decisions
            if result.get("policy_summary", {}).get("deployment_blocked"):
                result["exit_code"] = 1
                logger.warning("Deployment blocked by security policies")
            else:
                result["exit_code"] = 0
            
            return result
            
        except Exception as e:
            logger.error(f"Scan ingestion failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "exit_code": 2
            }
    
    async def policy_check(self, args) -> Dict[str, Any]:
        """
        Evaluate security policies for CI/CD gates
        Ultra-fast policy evaluation for deployment decisions
        """
        start_time = time.perf_counter()
        
        try:
            # Build policy context from CLI arguments
            context = PolicyContext(
                service_id=args.service_id,
                severity=args.severity,
                scanner_type=args.scanner_type,
                environment=args.environment,
                data_classification=args.data_classification or [],
                internet_facing=args.internet_facing,
                pci_scope=args.pci_scope,
                cvss_score=args.cvss_score,
                cve_id=args.cve_id,
                business_impact=args.business_impact
            )
            
            # Evaluate policy
            policy_result = await policy_engine.evaluate_policy(context)
            
            # Generate result
            total_time = time.perf_counter() - start_time
            
            result = {
                "status": "success",
                "policy_decision": policy_result.decision.value,
                "confidence": policy_result.confidence,
                "rationale": policy_result.rationale,
                "nist_ssdf_controls": policy_result.nist_ssdf_controls,
                "escalation_required": policy_result.escalation_required,
                "execution_time_ms": total_time * 1000,
                "hot_path_compliant": total_time * 1_000_000 < settings.HOT_PATH_TARGET_LATENCY_US
            }
            
            # Set exit code based on decision
            if policy_result.decision == PolicyDecision.BLOCK:
                result["exit_code"] = 1
            elif policy_result.decision in [PolicyDecision.DEFER, PolicyDecision.ESCALATE]:
                result["exit_code"] = 2
            else:
                result["exit_code"] = 0
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            return result
            
        except Exception as e:
            logger.error(f"Policy check failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "exit_code": 2
            }
    
    async def make_decision(self, args) -> Dict[str, Any]:
        """
        Make security decision for CI/CD pipeline
        Core FixOps Decision & Verification Engine operation
        """
        start_time = time.perf_counter()
        
        try:
            # Initialize decision engine
            from src.services.decision_engine import decision_engine, DecisionContext
            await decision_engine.initialize()
            
            # Read context data if provided
            business_context = {}
            if hasattr(args, 'context_file') and args.context_file:
                with open(args.context_file, 'r') as f:
                    business_context = json.load(f)
            
            # Get security findings from scan file
            security_findings = []
            if hasattr(args, 'scan_file') and args.scan_file:
                scan_data = await self.ingest_scan_results(args)
                security_findings = scan_data.get('findings', [])
            
            # Create decision context
            context = DecisionContext(
                service_name=args.service_name,
                environment=getattr(args, 'environment', 'production'),
                business_context=business_context,
                security_findings=security_findings
            )
            
            # Make decision
            decision_result = await decision_engine.make_decision(context)
            
            total_time = time.perf_counter() - start_time
            
            result = {
                "status": "success",
                "decision": decision_result.decision.value,
                "confidence_score": decision_result.confidence_score,
                "evidence_id": decision_result.evidence_id,
                "reasoning": decision_result.reasoning,
                "consensus_details": decision_result.consensus_details,
                "validation_results": decision_result.validation_results,
                "context_sources": decision_result.context_sources,
                "processing_time_ms": total_time * 1000,
                "processing_time_us": decision_result.processing_time_us,
                "hot_path_compliant": decision_result.processing_time_us < settings.HOT_PATH_TARGET_LATENCY_US
            }
            
            # Set exit code for CI/CD
            if decision_result.decision == DecisionOutcome.BLOCK:
                result["exit_code"] = 1
            elif decision_result.decision == DecisionOutcome.DEFER:
                result["exit_code"] = 2  
            else:
                result["exit_code"] = 0
            
            if hasattr(args, 'output_file') and args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            return result
            
        except Exception as e:
            logger.error(f"Decision making failed: {str(e)}")
            return {
                "status": "error", 
                "decision": "DEFER",
                "error": str(e),
                "exit_code": 2
            }
    
    async def get_evidence(self, args) -> Dict[str, Any]:
        """Retrieve evidence record from Evidence Lake"""
        try:
            from src.services.cache_service import CacheService
            cache = CacheService.get_instance()
            
            evidence = await cache.get(f"evidence:{args.evidence_id}")
            if not evidence:
                return {
                    "status": "error",
                    "error": f"Evidence record {args.evidence_id} not found",
                    "exit_code": 1
                }
            
            result = {
                "status": "success",
                "evidence_id": args.evidence_id,
                "evidence_record": evidence,
                "exit_code": 0
            }
            
            if hasattr(args, 'output_file') and args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            return result
            
        except Exception as e:
            logger.error(f"Evidence retrieval failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "exit_code": 2
            }
    
    async def correlation_analysis(self, args) -> Dict[str, Any]:
        """
        Analyze finding correlations for noise reduction
        High-performance correlation analysis
        """
        start_time = time.perf_counter()
        
        try:
            # Get findings for correlation
            findings = await self._get_findings_for_correlation(
                service_id=args.service_id,
                time_window_hours=args.time_window_hours,
                severity_filter=args.severity_filter
            )
            
            if len(findings) < 2:
                return {
                    "status": "success",
                    "message": "Not enough findings for correlation analysis",
                    "exit_code": 0
                }
            
            # Run correlation analysis
            finding_ids = [f.id for f in findings]
            correlation_results = await correlation_engine.batch_correlate_findings(finding_ids)
            
            # Calculate noise reduction metrics
            noise_reduction = await correlation_engine.calculate_noise_reduction(args.time_window_hours)
            
            # Generate correlation summary
            correlation_by_type = {}
            for result in correlation_results:
                corr_type = result.correlation_type
                correlation_by_type[corr_type] = correlation_by_type.get(corr_type, 0) + 1
            
            total_time = time.perf_counter() - start_time
            
            result = {
                "status": "success",
                "findings_analyzed": len(findings),
                "correlations_found": len(correlation_results),
                "noise_reduction_metrics": noise_reduction,
                "correlation_by_type": correlation_by_type,
                "processing_time_ms": total_time * 1000,
                "performance_metrics": {
                    "correlations_per_second": len(correlation_results) / total_time if total_time > 0 else 0
                },
                "exit_code": 0
            }
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            return result
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "exit_code": 2
            }
    
    async def health_check(self, args) -> Dict[str, Any]:
        """
        Perform system health check for CI/CD monitoring
        Ultra-fast health validation
        """
        start_time = time.perf_counter()
        
        try:
            health_checks = {}
            
            # Database health
            db_healthy = await DatabaseManager.health_check()
            health_checks["database"] = {
                "healthy": db_healthy,
                "latency_ms": 0  # Would measure actual latency
            }
            
            # Cache health
            cache = CacheService.get_instance()
            cache_healthy = await cache.ping()
            health_checks["cache"] = {
                "healthy": cache_healthy,
                "stats": await cache.get_cache_stats() if cache_healthy else {}
            }
            
            # Policy engine health
            policy_stats = await policy_engine.get_policy_stats()
            health_checks["policy_engine"] = {
                "healthy": True,
                "stats": policy_stats
            }
            
            # Correlation engine health
            correlation_stats = await correlation_engine.get_correlation_stats()
            health_checks["correlation_engine"] = {
                "healthy": True,
                "stats": correlation_stats
            }
            
            # Overall health
            overall_healthy = all(check.get("healthy", False) for check in health_checks.values())
            
            total_time = time.perf_counter() - start_time
            
            result = {
                "status": "healthy" if overall_healthy else "unhealthy",
                "health_checks": health_checks,
                "performance_metrics": {
                    "health_check_time_ms": total_time * 1000,
                    "hot_path_compliant": total_time * 1_000_000 < settings.HOT_PATH_TARGET_LATENCY_US
                },
                "exit_code": 0 if overall_healthy else 1
            }
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
            
            return result
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "exit_code": 2
            }
    
    # Helper methods
    async def _parse_sarif(self, sarif_content: str) -> Dict[str, Any]:
        """Parse SARIF format scan results"""
        sarif_data = json.loads(sarif_content)
        
        findings = []
        for run in sarif_data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {}).get("text", "")
                level = result.get("level", "note")
                
                # Map SARIF level to severity
                severity_mapping = {
                    "error": "high",
                    "warning": "medium", 
                    "note": "low",
                    "info": "info"
                }
                
                locations = result.get("locations", [])
                file_path = None
                line_number = None
                
                if locations:
                    location = locations[0]
                    physical_location = location.get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    file_path = artifact_location.get("uri")
                    
                    region = physical_location.get("region", {})
                    line_number = region.get("startLine")
                
                findings.append({
                    "rule_id": rule_id,
                    "title": message,
                    "description": message,
                    "severity": severity_mapping.get(level, "low"),
                    "category": result.get("ruleIndex", 0),
                    "file_path": file_path,
                    "line_number": line_number,
                    "scanner_name": tool_name
                })
        
        return {"findings": findings}
    
    async def _get_or_create_service(self, service_name: str, environment: str, repository_url: Optional[str] = None) -> Service:
        """Get or create service record"""
        async with DatabaseManager.get_session_context() as session:
            from sqlalchemy import select
            
            # Try to find existing service
            result = await session.execute(
                select(Service).where(
                    Service.name == service_name,
                    Service.environment == environment
                )
            )
            service = result.scalar_one_or_none()
            
            if not service:
                # Create new service
                service = Service(
                    name=service_name,
                    business_capability="Unknown", 
                    data_classification=["internal"],
                    environment=environment,
                    owner_team="Unknown",
                    owner_email="unknown@example.com",
                    repository_url=repository_url
                )
                session.add(service)
                await session.commit()
                await session.refresh(service)
            
            return service
    
    async def _process_findings_batch(self, findings_data: List[Dict], service: Service, scanner_type: str, scanner_name: str) -> List[SecurityFinding]:
        """Process a batch of findings for performance"""
        findings = []
        
        async with DatabaseManager.get_session_context() as session:
            for finding_data in findings_data:
                # Create finding record
                finding = SecurityFinding(
                    service_id=service.id,
                    scanner_type=scanner_type,
                    scanner_name=scanner_name,
                    rule_id=finding_data.get("rule_id", "unknown"),
                    title=finding_data.get("title", "Unknown vulnerability"),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "low"),
                    category=finding_data.get("category", "unknown"),
                    file_path=finding_data.get("file_path"),
                    line_number=finding_data.get("line_number"),
                    cwe_id=finding_data.get("cwe_id"),
                    cve_id=finding_data.get("cve_id"),
                    cvss_score=finding_data.get("cvss_score"),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    status="open"
                )
                
                session.add(finding)
                findings.append(finding)
            
            await session.commit()
        
        return findings
    
    async def _create_policy_context(self, finding: SecurityFinding, service: Service) -> PolicyContext:
        """Create policy context from finding and service"""
        return PolicyContext(
            finding_id=finding.id,
            service_id=service.id,
            severity=finding.severity,
            scanner_type=finding.scanner_type,
            environment=service.environment,
            data_classification=service.data_classification,
            internet_facing=service.internet_facing,
            pci_scope=service.pci_scope,
            cvss_score=finding.cvss_score,
            cve_id=finding.cve_id,
            business_impact=finding.business_impact
        )
    
    # Additional helper method stubs
    async def _get_findings_for_fix_generation(self, **kwargs) -> List[SecurityFinding]:
        """Get findings for fix generation"""
        # Implementation would query database based on filters
        return []
    
    async def _get_findings_for_correlation(self, **kwargs) -> List[SecurityFinding]:
        """Get findings for correlation analysis"""
        # Implementation would query database based on filters
        return []
    
    async def _get_service_by_id(self, service_id: str) -> Optional[Service]:
        """Get service by ID"""
        # Implementation would query database
        return None
    
    async def _generate_pr_patches(self, fixes: List[Dict], output_dir: str) -> List[str]:
        """Generate pull request patches from fixes"""
        # Implementation would generate actual PR patches
        return []


def create_parser():
    """Create argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="FixOps Enterprise CLI - Decision & Verification Engine (NOT Fix Engine)",
        epilog="""
Examples:
  # Make security decision for CI/CD pipeline (Demo Mode)
  fixops make-decision --service-name payment-service --environment production --scan-file sarif-results.json

  # Production mode with real integrations
  fixops make-decision --service-name payment-service --production-mode --scan-file sarif-results.json

  # Toggle to production mode for real data
  export FIXOPS_DEMO_MODE=false

  # Get evidence record
  fixops get-evidence --evidence-id EVD-2024-0847

  ⚠️  MODES:
  🎭 DEMO MODE (default): Uses simulated data for showcase/testing
  🏭 PRODUCTION MODE: Uses real Jira/Confluence/Vector DB integrations
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global demo mode flag
    parser.add_argument("--demo-mode", action="store_true", help="Force demo mode (simulated data)")
    parser.add_argument("--production-mode", action="store_true", help="Force production mode (real integrations)")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest security scan results")
    ingest_parser.add_argument("--scan-file", required=True, help="Path to scan results file")
    ingest_parser.add_argument("--format", choices=["sarif", "json"], default="sarif", help="Scan results format")
    ingest_parser.add_argument("--service-name", required=True, help="Service name")
    ingest_parser.add_argument("--environment", choices=["dev", "staging", "production"], required=True, help="Environment")
    ingest_parser.add_argument("--scanner-type", choices=["sast", "sca", "dast", "iast", "iac", "container"], required=True, help="Scanner type")
    ingest_parser.add_argument("--scanner-name", required=True, help="Scanner name")
    ingest_parser.add_argument("--repository-url", help="Repository URL")
    ingest_parser.add_argument("--enable-correlation", action="store_true", help="Enable correlation analysis")
    ingest_parser.add_argument("--enable-policy-evaluation", action="store_true", help="Enable policy evaluation")
    ingest_parser.add_argument("--output-file", help="Output file for results")
    
    # Policy check command
    policy_parser = subparsers.add_parser("policy-check", help="Evaluate security policies")
    policy_parser.add_argument("--service-id", help="Service ID")
    policy_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Finding severity")
    policy_parser.add_argument("--scanner-type", choices=["sast", "sca", "dast", "iast", "iac"], help="Scanner type")
    policy_parser.add_argument("--environment", choices=["dev", "staging", "production"], help="Environment")
    policy_parser.add_argument("--data-classification", nargs="+", choices=["pci", "pii", "phi", "confidential"], help="Data classifications")
    policy_parser.add_argument("--internet-facing", action="store_true", help="Internet-facing service")
    policy_parser.add_argument("--pci-scope", action="store_true", help="PCI-scoped service") 
    policy_parser.add_argument("--cvss-score", type=float, help="CVSS score")
    policy_parser.add_argument("--cve-id", help="CVE ID")
    policy_parser.add_argument("--business-impact", help="Business impact description")
    policy_parser.add_argument("--output-file", help="Output file for results")
    
    # Decision engine command
    decision_parser = subparsers.add_parser("make-decision", help="Make security decision for CI/CD pipeline")
    decision_parser.add_argument("--service-name", required=True, help="Service name")
    decision_parser.add_argument("--environment", default="production", choices=["production", "staging", "development"], help="Environment")
    decision_parser.add_argument("--scan-file", help="Security scan results file")
    decision_parser.add_argument("--context-file", help="Business context JSON file") 
    decision_parser.add_argument("--sbom-file", help="SBOM file for criticality assessment")
    decision_parser.add_argument("--confidence-threshold", type=float, default=0.85, help="Confidence threshold (default: 85%)")
    decision_parser.add_argument("--output-file", help="Output file for decision results")
    
    # Evidence lookup command  
    evidence_parser = subparsers.add_parser("get-evidence", help="Retrieve evidence record")
    evidence_parser.add_argument("--evidence-id", required=True, help="Evidence ID")
    evidence_parser.add_argument("--output-file", help="Output file for evidence")
    
    # Correlation command (updated for decision context)
    corr_parser = subparsers.add_parser("correlate", help="Analyze finding correlations for decision context")
    corr_parser.add_argument("--service-id", help="Service ID")
    corr_parser.add_argument("--time-window-hours", type=int, default=24, help="Time window in hours")
    corr_parser.add_argument("--severity-filter", nargs="+", choices=["critical", "high", "medium", "low"], help="Severity filter")
    corr_parser.add_argument("--output-file", help="Output file for results")
    
    # Health check command
    health_parser = subparsers.add_parser("health", help="System health check")
    health_parser.add_argument("--output-file", help="Output file for results")
    
    return parser


async def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = FixOpsCLI()
    
    try:
        await cli.initialize()
        
        # Route to appropriate command handler
        if args.command == "ingest":
            result = await cli.ingest_scan_results(args)
        elif args.command == "policy-check":
            result = await cli.policy_check(args)
        elif args.command == "make-decision":
            result = await cli.make_decision(args)
        elif args.command == "get-evidence":
            result = await cli.get_evidence(args)
        elif args.command == "correlate":
            result = await cli.correlation_analysis(args)
        elif args.command == "health":
            result = await cli.health_check(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
        
        # Output result
        if not args.output_file:
            print(json.dumps(result, indent=2, default=str))
        
        # Set exit code
        exit_code = result.get("exit_code", 0)
        sys.exit(exit_code)
        
    except Exception as e:
        logger.error(f"CLI execution failed: {str(e)}")
        print(json.dumps({"status": "error", "error": str(e)}, indent=2))
        sys.exit(2)
    finally:
        await cli.cleanup()


if __name__ == "__main__":
    asyncio.run(main())