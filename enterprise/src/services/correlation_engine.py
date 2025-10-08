"""
FixOps Correlation Engine - Core intelligence for noise reduction and finding correlation
Performance-optimized for 299μs hot path operations with AI-powered insights
"""

import asyncio
import time
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import structlog

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv
from src.services.chatgpt_client import ChatGPTChatSession, UserMessage, get_primary_llm_api_key
from src.db.session import DatabaseManager
from src.models.security_sqlite import SecurityFinding, FindingCorrelation, Service
from src.services.cache_service import CacheService
from src.utils.logger import PerformanceLogger

# Load environment variables
load_dotenv()

logger = structlog.get_logger()


@dataclass
class CorrelationResult:
    """Result of correlation analysis"""
    finding_id: str
    correlated_findings: List[str]
    correlation_type: str
    confidence_score: float
    noise_reduction_factor: float
    root_cause: str


class CorrelationEngine:
    """
    High-performance correlation engine for security findings
    Implements multiple correlation strategies with sub-millisecond performance
    """
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.correlation_strategies = [
            self._correlate_by_fingerprint,
            self._correlate_by_location,
            self._correlate_by_pattern,
            self._correlate_by_root_cause,
            self._correlate_by_vulnerability
        ]
        # Initialize LLM for AI-powered correlation insights
        self.llm_chat = None
        self._initialize_llm()
        
    def _initialize_llm(self):
        """Initialize LLM for advanced correlation analysis"""
        try:
            api_key = get_primary_llm_api_key()
            if api_key:
                self.llm_chat = ChatGPTChatSession(
                    api_key=api_key,
                    session_id="correlation_engine_session",
                    system_message="""You are an expert DevSecOps analyst specialized in security finding correlation and deduplication.
                    Your role is to analyze security findings and provide:
                    1. Correlation insights between findings
                    2. Risk assessment and prioritization
                    3. Root cause analysis suggestions
                    4. Noise reduction recommendations

                    Always provide concise, actionable analysis focused on reducing security alert fatigue.""",
                    model="gpt-4o-mini",
                    max_tokens=700,
                    temperature=0.25,
                )
                logger.info("LLM correlation engine initialized successfully with ChatGPT")
            else:
                logger.warning("No ChatGPT API key found, using rule-based correlation only")

        except Exception as e:
            logger.error(f"Failed to initialize ChatGPT correlation helper: {str(e)}")
            self.llm_chat = None
    
    async def correlate_finding(self, finding_id: str, force_refresh: bool = False) -> Optional[CorrelationResult]:
        """
        Correlate a single finding with existing findings
        Hot path optimized for 299μs target
        """
        start_time = time.perf_counter()
        
        try:
            # Check cache first for hot path performance
            cache_key = f"correlation:{finding_id}"
            if not force_refresh:
                cached_result = await self.cache.get(cache_key)
                if cached_result:
                    PerformanceLogger.log_hot_path_performance(
                        "correlation_cache_hit",
                        (time.perf_counter() - start_time) * 1_000_000
                    )
                    return CorrelationResult(**cached_result)
            
            # Get finding with optimized query
            async with DatabaseManager.get_session_context() as session:
                finding = await self._get_finding_optimized(session, finding_id)
                if not finding:
                    return None
                
                # Run correlation strategies in parallel
                correlation_tasks = [
                    strategy(session, finding) for strategy in self.correlation_strategies
                ]
                
                correlation_results = await asyncio.gather(*correlation_tasks, return_exceptions=True)
                
                # Process results and determine best correlation
                best_correlation = self._select_best_correlation(correlation_results)
                
                if best_correlation:
                    # Cache result for performance
                    await self.cache.set(cache_key, best_correlation.__dict__, ttl=300)
                    
                    # Store in database for persistence
                    await self._store_correlation(session, best_correlation)
            
            # Log performance metrics
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            PerformanceLogger.log_hot_path_performance(
                "correlation_analysis",
                latency_us,
                additional_context={"finding_id": finding_id}
            )
            
            return best_correlation
            
        except Exception as e:
            logger.error(f"Correlation failed for finding {finding_id}: {str(e)}")
            return None
    
    async def batch_correlate_findings(self, finding_ids: List[str]) -> List[CorrelationResult]:
        """
        Batch correlate multiple findings for efficiency
        Optimized for high-throughput processing
        """
        start_time = time.perf_counter()
        
        # Process in parallel batches
        batch_size = 10
        results = []
        
        for i in range(0, len(finding_ids), batch_size):
            batch = finding_ids[i:i + batch_size]
            batch_tasks = [self.correlate_finding(fid) for fid in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Filter out None and exceptions
            valid_results = [r for r in batch_results if isinstance(r, CorrelationResult)]
            results.extend(valid_results)
        
        # Log batch performance
        total_time = time.perf_counter() - start_time
        logger.info(
            "Batch correlation completed",
            total_findings=len(finding_ids),
            correlated_findings=len(results),
            total_time_ms=total_time * 1000,
            avg_time_per_finding_us=(total_time / len(finding_ids)) * 1_000_000
        )
        
        return results
    
    async def _get_finding_optimized(self, session: AsyncSession, finding_id: str) -> Optional[SecurityFinding]:
        """Get finding with optimized query for hot path performance"""
        result = await session.execute(
            select(SecurityFinding)
            .where(SecurityFinding.id == finding_id)
            .limit(1)
        )
        return result.scalar_one_or_none()
    
    async def _correlate_by_fingerprint(self, session: AsyncSession, finding: SecurityFinding) -> Optional[CorrelationResult]:
        """Correlate findings by exact fingerprint match - fastest correlation"""
        if not finding.fingerprint:
            return None
        
        # Find exact fingerprint matches
        result = await session.execute(
            select(SecurityFinding.id)
            .where(
                and_(
                    SecurityFinding.fingerprint == finding.fingerprint,
                    SecurityFinding.id != finding.id,
                    SecurityFinding.status.in_(["open", "in_progress"])
                )
            )
            .limit(100)
        )
        
        matches = [row[0] for row in result.fetchall()]
        
        if len(matches) >= 2:  # At least 2 other findings for meaningful correlation
            return CorrelationResult(
                finding_id=finding.id,
                correlated_findings=matches,
                correlation_type="exact_fingerprint",
                confidence_score=0.95,
                noise_reduction_factor=len(matches) / (len(matches) + 1),
                root_cause="identical_security_pattern"
            )
        
        return None
    
    async def _correlate_by_location(self, session: AsyncSession, finding: SecurityFinding) -> Optional[CorrelationResult]:
        """Correlate findings by file/location proximity"""
        if not finding.file_path:
            return None
        
        # Find findings in same file or nearby lines
        conditions = [SecurityFinding.file_path == finding.file_path]
        
        if finding.line_number:
            # Allow ±10 lines for proximity matching
            conditions.append(
                and_(
                    SecurityFinding.line_number.between(
                        finding.line_number - 10,
                        finding.line_number + 10
                    ),
                    SecurityFinding.file_path.like(f"%{finding.file_path.split('/')[-1]}%")
                )
            )
        
        result = await session.execute(
            select(SecurityFinding.id, SecurityFinding.file_path, SecurityFinding.line_number)
            .where(
                and_(
                    or_(*conditions),
                    SecurityFinding.id != finding.id,
                    SecurityFinding.service_id == finding.service_id,
                    SecurityFinding.status.in_(["open", "in_progress"])
                )
            )
            .limit(50)
        )
        
        matches = [row[0] for row in result.fetchall()]
        
        if len(matches) >= 1:
            confidence = 0.8 if finding.line_number else 0.6
            return CorrelationResult(
                finding_id=finding.id,
                correlated_findings=matches,
                correlation_type="location_proximity",
                confidence_score=confidence,
                noise_reduction_factor=len(matches) / (len(matches) + 2),
                root_cause="code_location_cluster"
            )
        
        return None
    
    async def _correlate_by_pattern(self, session: AsyncSession, finding: SecurityFinding) -> Optional[CorrelationResult]:
        """Correlate findings by rule pattern and scanner type"""
        result = await session.execute(
            select(SecurityFinding.id)
            .where(
                and_(
                    SecurityFinding.rule_id == finding.rule_id,
                    SecurityFinding.scanner_type == finding.scanner_type,
                    SecurityFinding.severity == finding.severity,
                    SecurityFinding.id != finding.id,
                    SecurityFinding.status.in_(["open", "in_progress"])
                )
            )
            .limit(50)
        )
        
        matches = [row[0] for row in result.fetchall()]
        
        if len(matches) >= 2:
            return CorrelationResult(
                finding_id=finding.id,
                correlated_findings=matches,
                correlation_type="rule_pattern",
                confidence_score=0.7,
                noise_reduction_factor=len(matches) / (len(matches) + 3),
                root_cause="common_vulnerability_pattern"
            )
        
        return None
    
    async def _correlate_by_root_cause(self, session: AsyncSession, finding: SecurityFinding) -> Optional[CorrelationResult]:
        """Correlate findings by potential root cause analysis"""
        
        # Define root cause patterns
        root_cause_patterns = {
            "input_validation": ["injection", "xss", "traversal", "overflow"],
            "authentication": ["auth", "login", "session", "token"],
            "authorization": ["access", "privilege", "permission", "acl"],
            "crypto": ["crypto", "ssl", "tls", "hash", "encrypt"],
            "configuration": ["config", "default", "hardcoded", "exposure"]
        }
        
        # Determine root cause category
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        root_cause_category = None
        for category, keywords in root_cause_patterns.items():
            if any(keyword in title_lower or keyword in desc_lower for keyword in keywords):
                root_cause_category = category
                break
        
        if not root_cause_category:
            return None
        
        # Find other findings with same root cause
        keywords = root_cause_patterns[root_cause_category]
        conditions = []
        
        for keyword in keywords:
            conditions.extend([
                SecurityFinding.title.ilike(f"%{keyword}%"),
                SecurityFinding.description.ilike(f"%{keyword}%")
            ])
        
        result = await session.execute(
            select(SecurityFinding.id)
            .where(
                and_(
                    or_(*conditions),
                    SecurityFinding.id != finding.id,
                    SecurityFinding.service_id == finding.service_id,
                    SecurityFinding.status.in_(["open", "in_progress"])
                )
            )
            .limit(30)
        )
        
        matches = [row[0] for row in result.fetchall()]
        
        if len(matches) >= 1:
            return CorrelationResult(
                finding_id=finding.id,
                correlated_findings=matches,
                correlation_type="root_cause",
                confidence_score=0.6,
                noise_reduction_factor=len(matches) / (len(matches) + 4),
                root_cause=root_cause_category
            )
        
        return None
    
    async def _correlate_by_vulnerability(self, session: AsyncSession, finding: SecurityFinding) -> Optional[CorrelationResult]:
        """Correlate findings by CVE/CWE vulnerability taxonomy"""
        conditions = []
        
        if finding.cve_id:
            conditions.append(SecurityFinding.cve_id == finding.cve_id)
        
        if finding.cwe_id:
            conditions.append(SecurityFinding.cwe_id == finding.cwe_id)
        
        if not conditions:
            return None
        
        result = await session.execute(
            select(SecurityFinding.id)
            .where(
                and_(
                    or_(*conditions),
                    SecurityFinding.id != finding.id,
                    SecurityFinding.status.in_(["open", "in_progress"])
                )
            )
            .limit(50)
        )
        
        matches = [row[0] for row in result.fetchall()]
        
        if len(matches) >= 1:
            confidence = 0.9 if finding.cve_id else 0.7
            return CorrelationResult(
                finding_id=finding.id,
                correlated_findings=matches,
                correlation_type="vulnerability_taxonomy",
                confidence_score=confidence,
                noise_reduction_factor=len(matches) / (len(matches) + 2),
                root_cause="known_vulnerability"
            )
        
        return None
    
    def _select_best_correlation(self, correlation_results: List[Any]) -> Optional[CorrelationResult]:
        """Select the best correlation result based on confidence and noise reduction"""
        valid_results = [r for r in correlation_results if isinstance(r, CorrelationResult)]
        
        if not valid_results:
            return None
        
        # Score correlations by confidence and noise reduction
        def score_correlation(correlation: CorrelationResult) -> float:
            return (
                correlation.confidence_score * 0.7 +
                correlation.noise_reduction_factor * 0.3 +
                len(correlation.correlated_findings) * 0.01  # Slight bonus for more correlations
            )
        
        return max(valid_results, key=score_correlation)
    
    async def _store_correlation(self, session: AsyncSession, correlation: CorrelationResult) -> None:
        """Store correlation result in database for persistence"""
        try:
            # Create correlation records
            for correlated_id in correlation.correlated_findings:
                correlation_record = FindingCorrelation(
                    finding_id=correlation.finding_id,
                    correlated_finding_id=correlated_id,
                    correlation_type=correlation.correlation_type,
                    confidence_score=correlation.confidence_score,
                    correlation_reason=correlation.root_cause
                )
                session.add(correlation_record)
            
        except Exception as e:
            logger.error(f"Failed to store correlation: {str(e)}")
    
    async def get_correlation_stats(self) -> Dict[str, Any]:
        """Get correlation engine performance statistics"""
        async with DatabaseManager.get_session_context() as session:
            # Total correlations
            total_correlations = await session.execute(
                select(func.count(FindingCorrelation.id))
            )
            
            # Correlations by type
            correlations_by_type = await session.execute(
                select(
                    FindingCorrelation.correlation_type,
                    func.count(FindingCorrelation.id)
                ).group_by(FindingCorrelation.correlation_type)
            )
            
            # Average confidence
            avg_confidence = await session.execute(
                select(func.avg(FindingCorrelation.confidence_score))
            )
            
            return {
                "total_correlations": total_correlations.scalar() or 0,
                "correlations_by_type": dict(correlations_by_type.fetchall()),
                "average_confidence": float(avg_confidence.scalar() or 0),
                "cache_stats": await self.cache.get_cache_stats()
            }
    
    async def calculate_noise_reduction(self, time_window_hours: int = 24) -> Dict[str, float]:
        """Calculate noise reduction metrics over time window"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        async with DatabaseManager.get_session_context() as session:
            # Total findings in window
            total_findings = await session.execute(
                select(func.count(SecurityFinding.id))
                .where(SecurityFinding.created_at >= cutoff_time)
            )
            
            # Correlated findings (noise)
            correlated_findings = await session.execute(
                select(func.count(func.distinct(FindingCorrelation.correlated_finding_id)))
                .join(SecurityFinding, FindingCorrelation.finding_id == SecurityFinding.id)
                .where(SecurityFinding.created_at >= cutoff_time)
            )
            
            total = total_findings.scalar() or 0
            correlated = correlated_findings.scalar() or 0
            
            if total == 0:
                return {"noise_reduction_percentage": 0.0, "total_findings": 0, "correlated_findings": 0}
            
            noise_reduction = (correlated / total) * 100
            
            return {
                "noise_reduction_percentage": noise_reduction,
                "total_findings": total,
                "correlated_findings": correlated,
                "unique_findings": total - correlated
            }
    
    async def ai_enhanced_correlation(self, finding_id: str, context_findings: List[str] = None) -> Dict[str, Any]:
        """Use AI to provide enhanced correlation insights and recommendations"""
        if not self.llm_chat:
            return {"error": "AI correlation not available - LLM not initialized"}
            
        try:
            async with DatabaseManager.get_session_context() as session:
                # Get main finding
                main_finding = await self._get_finding_optimized(session, finding_id)
                if not main_finding:
                    return {"error": "Finding not found"}
                
                # Get context findings or find related ones
                if not context_findings:
                    # Get recent similar findings for context
                    result = await session.execute(
                        select(SecurityFinding)
                        .where(
                            and_(
                                SecurityFinding.service_id == main_finding.service_id,
                                SecurityFinding.id != finding_id,
                                SecurityFinding.status.in_(["open", "in_progress"]),
                                SecurityFinding.created_at >= datetime.utcnow() - timedelta(days=7)
                            )
                        )
                        .limit(5)
                    )
                    context_findings_objs = result.scalars().all()
                else:
                    # Get specific context findings
                    result = await session.execute(
                        select(SecurityFinding)
                        .where(SecurityFinding.id.in_(context_findings))
                    )
                    context_findings_objs = result.scalars().all()
                
                # Prepare data for AI analysis
                analysis_data = {
                    "main_finding": {
                        "id": main_finding.id,
                        "title": main_finding.title,
                        "description": main_finding.description,
                        "severity": main_finding.severity,
                        "scanner_type": main_finding.scanner_type,
                        "service_id": main_finding.service_id,
                        "file_path": main_finding.file_path,
                        "cve_id": main_finding.cve_id,
                        "cwe_id": main_finding.cwe_id
                    },
                    "context_findings": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity,
                            "scanner_type": f.scanner_type,
                            "file_path": f.file_path
                        } for f in context_findings_objs
                    ]
                }
                
                # Create AI analysis prompt
                prompt = f"""
                Analyze this security finding and provide correlation insights:

                MAIN FINDING:
                {json.dumps(analysis_data['main_finding'], indent=2)}

                CONTEXT FINDINGS:
                {json.dumps(analysis_data['context_findings'], indent=2)}

                Please provide analysis in JSON format with:
                1. "correlation_insights" - How this finding relates to context findings
                2. "risk_assessment" - Risk level and business impact assessment  
                3. "root_cause_analysis" - Likely root causes and patterns
                4. "prioritization" - Should this be high/medium/low priority and why
                5. "recommendations" - Specific actions to address this finding

                Focus on actionable insights that help reduce security noise and prioritize remediation efforts.
                """
                
                user_message = UserMessage(text=prompt)
                ai_response = await self.llm_chat.send_message(user_message)
                
                # Parse AI response
                try:
                    ai_insights = json.loads(ai_response)
                    return {
                        "finding_id": finding_id,
                        "ai_analysis": ai_insights,
                        "context_count": len(context_findings_objs),
                        "analysis_timestamp": datetime.utcnow().isoformat()
                    }
                except json.JSONDecodeError:
                    # Return raw text if JSON parsing fails
                    return {
                        "finding_id": finding_id,
                        "ai_analysis": {"raw_analysis": ai_response},
                        "context_count": len(context_findings_objs),
                        "analysis_timestamp": datetime.utcnow().isoformat()
                    }
                    
        except Exception as e:
            logger.error(f"AI correlation analysis failed: {str(e)}")
            return {"error": f"AI analysis failed: {str(e)}"}


# Global correlation engine instance
correlation_engine = CorrelationEngine()


async def correlate_finding_async(finding_id: str) -> Optional[CorrelationResult]:
    """Async wrapper for correlation engine"""
    return await correlation_engine.correlate_finding(finding_id)


async def batch_correlate_async(finding_ids: List[str]) -> List[CorrelationResult]:
    """Async wrapper for batch correlation"""
    return await correlation_engine.batch_correlate_findings(finding_ids)