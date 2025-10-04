"""
Real Vector Store Implementation with ChromaDB for Production Mode
- Demo Mode: Uses in-memory fallback with mock data
- Production Mode: Uses ChromaDB with real embeddings and similarity search
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import structlog

from src.config.settings import get_settings

logger = structlog.get_logger()
settings = get_settings()

@dataclass
class VectorRecord:
    id: str
    embedding: List[float]
    metadata: Dict[str, Any]
    similarity_score: float = 0.0

class VectorStore:
    async def initialize(self):
        """Initialize the vector store"""
        pass
    
    async def upsert(self, records: List[VectorRecord]):
        raise NotImplementedError

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        raise NotImplementedError
    
    async def add_security_patterns(self, patterns: List[Dict[str, Any]]):
        """Add security patterns to vector store"""
        records = []
        for pattern in patterns:
            # Generate embedding for security pattern
            embedding = await self._generate_embedding(pattern.get('text', ''))
            record = VectorRecord(
                id=pattern.get('id', str(uuid.uuid4())),
                embedding=embedding,
                metadata=pattern
            )
            records.append(record)
        
        await self.upsert(records)

    async def search_security_patterns(self, query_text: str, top_k: int = 5) -> List[VectorRecord]:
        """Search for similar security patterns"""
        query_embedding = await self._generate_embedding(query_text)
        return await self.search(query_embedding, top_k)

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text - implement in subclasses"""
        raise NotImplementedError

class DemoVectorStore(VectorStore):
    """Demo mode with in-memory storage and mock embeddings"""
    
    def __init__(self):
        self._memory_store: List[VectorRecord] = []
        self._initialized = False
    
    async def initialize(self):
        """Initialize with demo security patterns"""
        if self._initialized:
            return
            
        demo_patterns = [
            {
                'id': 'sql_injection_pattern_1',
                'text': 'SQL injection vulnerability in database query',
                'category': 'injection',
                'severity': 'high',
                'cwe_id': 'CWE-89',
                'mitre_techniques': ['T1190']
            },
            {
                'id': 'xss_pattern_1', 
                'text': 'Cross-site scripting vulnerability in web application',
                'category': 'injection',
                'severity': 'medium',
                'cwe_id': 'CWE-79',
                'mitre_techniques': ['T1059']
            },
            {
                'id': 'auth_bypass_pattern_1',
                'text': 'Authentication bypass vulnerability in login system',
                'category': 'authentication',
                'severity': 'critical',
                'cwe_id': 'CWE-287',
                'mitre_techniques': ['T1078']
            },
            {
                'id': 'crypto_weakness_pattern_1',
                'text': 'Weak cryptographic implementation vulnerability',
                'category': 'cryptography',
                'severity': 'high',
                'cwe_id': 'CWE-327',
                'mitre_techniques': ['T1552']
            }
        ]
        
        # Add demo patterns
        records = []
        for pattern in demo_patterns:
            embedding = await self._generate_embedding(pattern['text'])
            record = VectorRecord(
                id=pattern['id'],
                embedding=embedding,
                metadata=pattern
            )
            records.append(record)
        
        await self.upsert(records)
        self._initialized = True
        logger.info("🎭 Demo Vector Store initialized with security patterns", count=len(demo_patterns))

    async def upsert(self, records: List[VectorRecord]):
        """Store records in memory for demo"""
        for record in records:
            # Remove existing record with same ID
            self._memory_store = [r for r in self._memory_store if r.id != record.id]
            # Add new record
            self._memory_store.append(record)
        
        logger.info("Demo Vector Store upsert", count=len(records), total=len(self._memory_store))

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        """Demo cosine similarity search in memory"""
        if not self._memory_store:
            return []
            
        def cosine_similarity(a: List[float], b: List[float]) -> float:
            """Calculate cosine similarity between two vectors"""
            dot_product = sum(x * y for x, y in zip(a, b))
            magnitude_a = sum(x * x for x in a) ** 0.5
            magnitude_b = sum(y * y for y in b) ** 0.5
            return dot_product / (magnitude_a * magnitude_b + 1e-9)
        
        # Calculate similarities
        scored_records = []
        for record in self._memory_store:
            similarity = cosine_similarity(embedding, record.embedding)
            record_with_score = VectorRecord(
                id=record.id,
                embedding=record.embedding,
                metadata=record.metadata,
                similarity_score=similarity
            )
            scored_records.append(record_with_score)
        
        # Sort by similarity and return top_k
        scored_records.sort(key=lambda x: x.similarity_score, reverse=True)
        return scored_records[:top_k]

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate mock embedding for demo mode"""
        # Create deterministic mock embedding based on text hash
        import hashlib
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        # Convert hash to embedding vector
        embedding = []
        for i in range(0, len(text_hash), 2):
            hex_val = text_hash[i:i+2]
            embedding.append(int(hex_val, 16) / 255.0)
        
        # Pad or truncate to 16 dimensions
        while len(embedding) < 16:
            embedding.append(0.0)
        
        return embedding[:16]

class ChromaDBVectorStore(VectorStore):
    """Production mode with real ChromaDB and embeddings"""
    
    def __init__(self):
        self.client = None
        self.collection = None
        self.embedding_function = None
        self._initialized = False
    
    async def initialize(self):
        """Initialize ChromaDB client and collection"""
        if self._initialized:
            return
            
        try:
            import chromadb
            from chromadb.config import Settings
            
            # Initialize ChromaDB client
            self.client = chromadb.Client(Settings(
                anonymized_telemetry=False,
                is_persistent=True,
                persist_directory="/app/data/chromadb"
            ))
            
            # Create or get collection
            self.collection = self.client.get_or_create_collection(
                name="security_patterns",
                metadata={"description": "FixOps security patterns and vulnerability knowledge"}
            )
            
            # Initialize embedding function
            await self._initialize_embeddings()
            
            # Load initial security patterns
            await self._load_initial_patterns()
            
            self._initialized = True
            logger.info("✅ ChromaDB Vector Store initialized successfully")
            
        except Exception as e:
            logger.error(f"ChromaDB initialization failed: {e}")
            raise

    async def _initialize_embeddings(self):
        """Initialize sentence transformers for embeddings"""
        try:
            # Try to import sentence-transformers
            from sentence_transformers import SentenceTransformer
            
            # Use a lightweight model for security text embedding
            self.embedding_function = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("✅ Sentence Transformers initialized for embeddings")
            
        except ImportError:
            logger.warning("Sentence Transformers not available, using fallback embeddings")
            self.embedding_function = None

    async def _load_initial_patterns(self):
        """Load initial security patterns into ChromaDB"""
        initial_patterns = [
            {
                'id': 'cwe_89_sql_injection',
                'text': 'SQL injection vulnerability allows attackers to execute malicious SQL commands through application inputs, potentially exposing sensitive database information',
                'category': 'injection',
                'severity': 'high',
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021',
                'mitre_techniques': ['T1190', 'T1212'],
                'fix_guidance': 'Use parameterized queries, input validation, and least-privilege database access'
            },
            {
                'id': 'cwe_79_xss',
                'text': 'Cross-site scripting (XSS) vulnerability enables attackers to inject malicious scripts into web pages viewed by users',
                'category': 'injection',
                'severity': 'medium',
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021',
                'mitre_techniques': ['T1059.007'],
                'fix_guidance': 'Implement output encoding, Content Security Policy, and input validation'
            },
            {
                'id': 'cwe_287_auth_bypass',
                'text': 'Authentication bypass vulnerability allows unauthorized access by circumventing login mechanisms',
                'category': 'authentication',
                'severity': 'critical',
                'cwe_id': 'CWE-287',
                'owasp_category': 'A07:2021',
                'mitre_techniques': ['T1078', 'T1110'],
                'fix_guidance': 'Strengthen authentication mechanisms, implement MFA, and audit access controls'
            },
            {
                'id': 'cwe_327_crypto_weakness',
                'text': 'Cryptographic weakness involving use of broken or risky cryptographic algorithms',
                'category': 'cryptography', 
                'severity': 'high',
                'cwe_id': 'CWE-327',
                'owasp_category': 'A02:2021',
                'mitre_techniques': ['T1552.004'],
                'fix_guidance': 'Use current cryptographic standards, proper key management, and avoid deprecated algorithms'
            },
            {
                'id': 'cwe_22_path_traversal',
                'text': 'Path traversal vulnerability allows access to files outside intended directory through directory traversal sequences',
                'category': 'path_manipulation',
                'severity': 'high',
                'cwe_id': 'CWE-22',
                'owasp_category': 'A01:2021',
                'mitre_techniques': ['T1083'],
                'fix_guidance': 'Validate file paths, use allow-lists, and implement proper access controls'
            }
        ]
        
        # Check if patterns already exist
        existing_count = self.collection.count()
        if existing_count >= len(initial_patterns):
            logger.info(f"Security patterns already loaded: {existing_count} patterns in ChromaDB")
            return
        
        # Add patterns to ChromaDB
        await self.add_security_patterns(initial_patterns)
        logger.info(f"✅ Loaded {len(initial_patterns)} initial security patterns into ChromaDB")

    async def upsert(self, records: List[VectorRecord]):
        """Store records in ChromaDB"""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Prepare data for ChromaDB
            ids = [record.id for record in records]
            embeddings = [record.embedding for record in records]
            metadatas = [record.metadata for record in records]
            documents = [record.metadata.get('text', '') for record in records]
            
            # Upsert to ChromaDB
            self.collection.upsert(
                ids=ids,
                embeddings=embeddings,
                metadatas=metadatas,
                documents=documents
            )
            
            logger.info(f"✅ ChromaDB upserted {len(records)} records successfully")
            
        except Exception as e:
            logger.error(f"ChromaDB upsert failed: {e}")
            raise

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        """Search ChromaDB with embedding vector"""
        if not self._initialized:
            await self.initialize()
        
        try:
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=top_k,
                include=["metadatas", "documents", "distances", "embeddings"]
            )
            
            # Convert results to VectorRecord objects
            records = []
            if results and results['ids'] and len(results['ids']) > 0:
                for i, record_id in enumerate(results['ids'][0]):
                    record = VectorRecord(
                        id=record_id,
                        embedding=results['embeddings'][0][i] if results['embeddings'] else embedding,
                        metadata=results['metadatas'][0][i] if results['metadatas'] else {},
                        similarity_score=1.0 - results['distances'][0][i] if results['distances'] else 0.0  # Convert distance to similarity
                    )
                    records.append(record)
            
            logger.info(f"ChromaDB search returned {len(records)} results")
            return records
            
        except Exception as e:
            logger.error(f"ChromaDB search failed: {e}")
            return []

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate real embedding using sentence transformers"""
        if self.embedding_function:
            try:
                # Generate embedding using sentence transformers
                embedding = self.embedding_function.encode(text).tolist()
                return embedding
                
            except Exception as e:
                logger.error(f"Embedding generation failed: {e}")
        
        # Fallback to simple hash-based embedding
        return await self._fallback_embedding(text)

    async def _fallback_embedding(self, text: str) -> List[float]:
        """Fallback embedding generation using hash"""
        import hashlib
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        # Convert hash to embedding vector (384 dimensions like sentence transformers)
        embedding = []
        hash_repeated = (text_hash * 12)[:96]  # 96 hex chars = 384 float values / 4
        
        for i in range(0, len(hash_repeated), 2):
            hex_val = hash_repeated[i:i+2]
            embedding.append((int(hex_val, 16) - 128) / 128.0)  # Normalize to [-1, 1]
        
        # Ensure exactly 384 dimensions
        while len(embedding) < 384:
            embedding.append(0.0)
        
        return embedding[:384]

class VectorStoreFactory:
    """Factory for creating vector store instances based on mode"""
    
    @staticmethod  
    def create(settings=None) -> VectorStore:
        """Create vector store based on demo mode setting"""
        if settings is None:
            settings = get_settings()
        
        if settings.DEMO_MODE:
            logger.info("🎭 Creating Demo Vector Store (in-memory)")
            return DemoVectorStore()
        else:
            logger.info("🏭 Creating Production Vector Store (ChromaDB)")
            return ChromaDBVectorStore()

# Global vector store instance
_vector_store_instance: Optional[VectorStore] = None

async def get_vector_store() -> VectorStore:
    """Get singleton vector store instance"""
    global _vector_store_instance
    
    if _vector_store_instance is None:
        _vector_store_instance = VectorStoreFactory.create()
        await _vector_store_instance.initialize()
    
    return _vector_store_instance
