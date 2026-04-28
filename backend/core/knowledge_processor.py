"""
NeuroSploit v3 - Knowledge Processor

Pipeline: Upload → Extract Text → AI Summarize → Index by Vuln Type → Store.
Processes bug bounty papers, CVE documents, writeups, and lab reports
into structured knowledge the agent uses during testing.
"""
import json
import re
import uuid
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)

# Optional PDF support
try:
    from PyPDF2 import PdfReader
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False

KNOWLEDGE_DIR = Path("data/custom-knowledge")
UPLOADS_DIR = KNOWLEDGE_DIR / "uploads"
INDEX_FILE = KNOWLEDGE_DIR / "index.json"

SUPPORTED_FORMATS = {".pdf", ".md", ".txt", ".html", ".htm"}

# Standard vuln type keywords for classification
VULN_KEYWORDS = {
    "xss": ["xss", "cross-site scripting", "cross site scripting", "script injection", "reflected xss", "stored xss", "dom xss"],
    "sqli": ["sql injection", "sqli", "sql inject", "union select", "blind sql", "boolean-based", "time-based"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery", "internal request"],
    "idor": ["idor", "insecure direct object reference", "direct object reference", "horizontal privilege"],
    "rce": ["rce", "remote code execution", "command injection", "os command", "code execution"],
    "lfi": ["lfi", "local file inclusion", "file inclusion", "path traversal", "directory traversal"],
    "rfi": ["rfi", "remote file inclusion"],
    "csrf": ["csrf", "cross-site request forgery", "cross site request forgery"],
    "xxe": ["xxe", "xml external entity", "xml injection"],
    "ssti": ["ssti", "server-side template injection", "template injection"],
    "auth_bypass": ["auth bypass", "authentication bypass", "login bypass", "2fa bypass", "mfa bypass"],
    "open_redirect": ["open redirect", "url redirect", "redirect vulnerability"],
    "race_condition": ["race condition", "toctou", "time of check"],
    "deserialization": ["deserialization", "deserialize", "insecure deserialization", "pickle", "java serialization"],
    "graphql": ["graphql", "graphql injection", "introspection"],
    "nosql": ["nosql", "nosql injection", "mongodb injection"],
    "jwt": ["jwt", "json web token", "jwt attack", "jwt bypass"],
    "cors": ["cors", "cross-origin", "access-control-allow-origin"],
    "crlf": ["crlf", "crlf injection", "header injection"],
    "upload": ["file upload", "upload bypass", "unrestricted upload", "webshell"],
    "subdomain_takeover": ["subdomain takeover", "dangling dns"],
    "information_disclosure": ["information disclosure", "info leak", "data exposure", "sensitive data"],
    "privilege_escalation": ["privilege escalation", "privesc", "vertical privilege"],
    "bola": ["bola", "broken object level authorization"],
    "bfla": ["bfla", "broken function level authorization"],
    "api": ["api security", "api vulnerability", "rest api", "api abuse"],
    "websocket": ["websocket", "ws hijacking"],
    "cache_poisoning": ["cache poisoning", "web cache"],
    "prototype_pollution": ["prototype pollution", "__proto__"],
    "clickjacking": ["clickjacking", "ui redressing", "x-frame-options"],
}

AI_ANALYSIS_PROMPT = """You are a security research analyst. Analyze the following security document and extract structured knowledge for a penetration testing AI agent.

Document filename: {filename}

Document content (truncated):
{text}

Extract the following as JSON:
{{
    "title": "Short descriptive title for this document",
    "summary": "2-3 sentence summary of the key security findings/methodology",
    "vuln_types": ["list", "of", "vuln_types"],
    "knowledge_entries": [
        {{
            "vuln_type": "the_vuln_type",
            "methodology": "Step-by-step attack methodology described in the document",
            "payloads": ["specific payloads or PoC code mentioned"],
            "key_insights": "What makes this approach unique or effective",
            "bypass_techniques": ["any WAF/filter/defense bypasses described"]
        }}
    ]
}}

RULES:
- vuln_types must use standard identifiers: xss, sqli, ssrf, idor, rce, lfi, csrf, xxe, ssti, auth_bypass, open_redirect, race_condition, deserialization, graphql, nosql, jwt, cors, crlf, upload, subdomain_takeover, information_disclosure, privilege_escalation, bola, bfla, api, websocket, cache_poisoning, prototype_pollution, clickjacking
- Only extract information EXPLICITLY present in the document
- Do NOT fabricate payloads or methodologies not described in the text
- Each knowledge_entry should map to exactly one vuln_type
- If the document covers multiple vuln types, create separate entries for each
"""


class KnowledgeProcessor:
    """Processes uploaded security documents into indexed knowledge."""

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self._index = self._load_index()
        KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> dict:
        """Load or initialize the knowledge index."""
        if INDEX_FILE.exists():
            try:
                return json.loads(INDEX_FILE.read_text())
            except Exception as e:
                logger.warning(f"Failed to load knowledge index: {e}")
        return {"documents": [], "vuln_type_index": {}, "version": "1.0"}

    def _save_index(self):
        """Persist index to disk."""
        self._index["updated_at"] = datetime.utcnow().isoformat()
        INDEX_FILE.write_text(json.dumps(self._index, indent=2))

    async def process_upload(self, file_bytes: bytes, filename: str) -> dict:
        """Full pipeline for a single file upload."""
        ext = Path(filename).suffix.lower()
        if ext not in SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {ext}. Supported: {', '.join(SUPPORTED_FORMATS)}")

        # Generate unique ID
        doc_id = str(uuid.uuid4())[:12]

        # Save raw file
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        file_path = UPLOADS_DIR / f"{doc_id}_{safe_filename}"
        file_path.write_bytes(file_bytes)

        # Extract text
        text = self._extract_text(file_path, ext)
        if not text or len(text.strip()) < 50:
            file_path.unlink(missing_ok=True)
            raise ValueError("Document has insufficient text content (< 50 chars)")

        # AI analysis (or keyword-based fallback)
        if self.llm_client:
            analysis = await self._ai_analyze(text, filename)
        else:
            analysis = self._keyword_analyze(text, filename)

        # Build document entry
        doc_entry = {
            "id": doc_id,
            "filename": filename,
            "title": analysis.get("title", filename),
            "source_type": ext.lstrip("."),
            "uploaded_at": datetime.utcnow().isoformat(),
            "processed": True,
            "file_size_bytes": len(file_bytes),
            "summary": analysis.get("summary", ""),
            "vuln_types": analysis.get("vuln_types", []),
            "knowledge_entries": analysis.get("knowledge_entries", []),
        }

        # Add to index
        self._index_document(doc_entry)
        self._save_index()

        logger.info(f"Processed knowledge document: {filename} -> {len(doc_entry['knowledge_entries'])} entries")
        return doc_entry

    def _extract_text(self, file_path: Path, ext: str) -> str:
        """Extract text from file based on format."""
        if ext == ".pdf":
            return self._extract_text_pdf(file_path)
        elif ext in (".md", ".txt"):
            return self._extract_text_plaintext(file_path)
        elif ext in (".html", ".htm"):
            return self._extract_text_html(file_path)
        return ""

    def _extract_text_pdf(self, file_path: Path) -> str:
        """Extract text from PDF."""
        if not HAS_PYPDF2:
            logger.warning("PyPDF2 not installed - PDF extraction unavailable. Install: pip install PyPDF2")
            # Try reading as text fallback
            try:
                return file_path.read_text(errors="ignore")[:20000]
            except Exception:
                return ""
        try:
            reader = PdfReader(str(file_path))
            text_parts = []
            for page in reader.pages[:50]:  # Max 50 pages
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            return "\n\n".join(text_parts)
        except Exception as e:
            logger.warning(f"PDF extraction failed: {e}")
            return ""

    def _extract_text_plaintext(self, file_path: Path) -> str:
        """Read markdown or plain text file."""
        try:
            return file_path.read_text(errors="ignore")
        except Exception:
            return ""

    def _extract_text_html(self, file_path: Path) -> str:
        """Extract text from HTML by stripping tags."""
        try:
            html = file_path.read_text(errors="ignore")
            # Remove script and style blocks
            html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
            # Strip all tags
            text = re.sub(r'<[^>]+>', ' ', html)
            # Clean whitespace
            text = re.sub(r'\s+', ' ', text).strip()
            return text
        except Exception:
            return ""

    async def _ai_analyze(self, text: str, filename: str) -> dict:
        """Use LLM to extract structured knowledge."""
        truncated = text[:8000]
        prompt = AI_ANALYSIS_PROMPT.format(filename=filename, text=truncated)

        try:
            response = await self.llm_client.generate(prompt)
            # Parse JSON from response
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                data = json.loads(match.group())
                # Validate vuln_types
                valid_types = set(VULN_KEYWORDS.keys())
                data["vuln_types"] = [vt for vt in data.get("vuln_types", []) if vt in valid_types]
                for entry in data.get("knowledge_entries", []):
                    if entry.get("vuln_type") not in valid_types:
                        entry["vuln_type"] = data["vuln_types"][0] if data["vuln_types"] else "information_disclosure"
                return data
        except Exception as e:
            logger.warning(f"AI analysis failed, falling back to keyword analysis: {e}")

        return self._keyword_analyze(text, filename)

    def _keyword_analyze(self, text: str, filename: str) -> dict:
        """Fallback keyword-based analysis when no LLM available."""
        text_lower = text.lower()
        detected_types = []

        for vuln_type, keywords in VULN_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text_lower:
                    detected_types.append(vuln_type)
                    break

        if not detected_types:
            detected_types = ["information_disclosure"]

        # Extract title from first line or filename
        first_line = text.strip().split("\n")[0][:200]
        title = first_line if len(first_line) > 10 else filename

        # Build basic entries
        entries = []
        for vt in detected_types[:5]:  # Max 5 types
            entries.append({
                "vuln_type": vt,
                "methodology": self._extract_section(text, ["methodology", "steps", "approach", "technique"]),
                "payloads": self._extract_payloads(text),
                "key_insights": self._extract_section(text, ["insight", "key finding", "conclusion", "takeaway"]),
                "bypass_techniques": self._extract_payloads_by_pattern(text, ["bypass", "evasion", "waf", "filter"]),
            })

        return {
            "title": title.strip("#").strip(),
            "summary": text[:300].strip(),
            "vuln_types": detected_types,
            "knowledge_entries": entries,
        }

    def _extract_section(self, text: str, keywords: List[str]) -> str:
        """Extract text section near keywords."""
        text_lower = text.lower()
        for keyword in keywords:
            idx = text_lower.find(keyword)
            if idx >= 0:
                # Get surrounding context (up to 800 chars after keyword)
                start = max(0, idx - 50)
                end = min(len(text), idx + 800)
                return text[start:end].strip()
        return ""

    def _extract_payloads(self, text: str) -> List[str]:
        """Extract potential payloads from text."""
        payloads = []
        # Look for common payload patterns
        patterns = [
            r'`([^`]{5,200})`',  # Backtick-enclosed code
            r"'([^']{10,200})'",  # Single-quoted strings that look like payloads
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for m in matches:
                if any(indicator in m.lower() for indicator in
                       ["<script", "alert(", "onerror", "union select", "../", "{{",
                        "curl ", "wget ", "%00", "127.0.0.1", "169.254", "; cat",
                        "' or ", '" or ', "1=1", "exec(", "system("]):
                    payloads.append(m)
        return payloads[:20]  # Max 20 payloads

    def _extract_payloads_by_pattern(self, text: str, keywords: List[str]) -> List[str]:
        """Extract text fragments near specific keywords."""
        results = []
        text_lower = text.lower()
        for keyword in keywords:
            idx = text_lower.find(keyword)
            if idx >= 0:
                start = max(0, idx - 20)
                end = min(len(text), idx + 200)
                fragment = text[start:end].strip()
                if fragment:
                    results.append(fragment[:200])
        return results[:10]

    def _index_document(self, doc_entry: dict):
        """Add document to the index."""
        # Remove existing doc with same ID if re-processing
        self._index["documents"] = [
            d for d in self._index["documents"] if d["id"] != doc_entry["id"]
        ]
        self._index["documents"].append(doc_entry)

        # Update vuln_type_index
        for vt in doc_entry.get("vuln_types", []):
            if vt not in self._index["vuln_type_index"]:
                self._index["vuln_type_index"][vt] = []
            if doc_entry["id"] not in self._index["vuln_type_index"][vt]:
                self._index["vuln_type_index"][vt].append(doc_entry["id"])

    def get_documents(self) -> List[dict]:
        """Return all indexed documents (without full entries for list view)."""
        docs = []
        for d in self._index.get("documents", []):
            docs.append({
                "id": d["id"],
                "filename": d["filename"],
                "title": d["title"],
                "source_type": d["source_type"],
                "uploaded_at": d["uploaded_at"],
                "processed": d["processed"],
                "file_size_bytes": d["file_size_bytes"],
                "summary": d["summary"],
                "vuln_types": d["vuln_types"],
                "entries_count": len(d.get("knowledge_entries", [])),
            })
        return docs

    def get_document(self, doc_id: str) -> Optional[dict]:
        """Get a specific document with full entries."""
        for d in self._index.get("documents", []):
            if d["id"] == doc_id:
                return d
        return None

    def delete_document(self, doc_id: str) -> bool:
        """Remove document from index and delete uploaded file."""
        doc = self.get_document(doc_id)
        if not doc:
            return False

        # Remove from documents list
        self._index["documents"] = [
            d for d in self._index["documents"] if d["id"] != doc_id
        ]

        # Remove from vuln_type_index
        for vt, doc_ids in self._index.get("vuln_type_index", {}).items():
            if doc_id in doc_ids:
                doc_ids.remove(doc_id)

        # Delete uploaded file
        for f in UPLOADS_DIR.glob(f"{doc_id}_*"):
            f.unlink(missing_ok=True)

        self._save_index()
        return True

    def search_by_vuln_type(self, vuln_type: str, max_entries: int = 5) -> List[dict]:
        """Search knowledge entries by vulnerability type."""
        vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
        doc_ids = self._index.get("vuln_type_index", {}).get(vuln_key, [])
        if not doc_ids:
            return []

        entries = []
        for doc in self._index.get("documents", []):
            if doc["id"] in doc_ids:
                for ke in doc.get("knowledge_entries", []):
                    if ke.get("vuln_type") == vuln_key:
                        entry = dict(ke)
                        entry["source_document"] = doc["title"]
                        entry["source_id"] = doc["id"]
                        entries.append(entry)

        return entries[:max_entries]

    def get_stats(self) -> dict:
        """Get knowledge base statistics."""
        docs = self._index.get("documents", [])
        total_entries = sum(len(d.get("knowledge_entries", [])) for d in docs)
        vuln_types = list(self._index.get("vuln_type_index", {}).keys())

        # Calculate storage size
        storage_bytes = 0
        if UPLOADS_DIR.exists():
            for f in UPLOADS_DIR.iterdir():
                storage_bytes += f.stat().st_size

        return {
            "total_documents": len(docs),
            "total_entries": total_entries,
            "vuln_types_covered": sorted(vuln_types),
            "storage_bytes": storage_bytes,
        }

    def get_patterns_for_vuln(self, vuln_type: str, max_entries: int = 3) -> str:
        """Get formatted knowledge patterns for a vuln type (for LLM context injection)."""
        entries = self.search_by_vuln_type(vuln_type, max_entries)
        if not entries:
            return ""

        result = "\n\n=== CUSTOM KNOWLEDGE (User-Uploaded Research) ===\n"
        for i, entry in enumerate(entries, 1):
            result += f"--- Research {i}: {entry.get('source_document', 'Unknown')} ---\n"
            if entry.get("methodology"):
                result += f"Methodology: {entry['methodology'][:800]}\n"
            if entry.get("payloads"):
                result += f"Payloads: {', '.join(entry['payloads'][:5])}\n"
            if entry.get("key_insights"):
                result += f"Key Insights: {entry['key_insights'][:400]}\n"
            if entry.get("bypass_techniques"):
                result += f"Bypass Techniques: {', '.join(entry['bypass_techniques'][:3])}\n"
            result += "\n"
        result += "=== END CUSTOM KNOWLEDGE ===\n"
        return result
