#!/usr/bin/env python3
"""
Knowledge Augmentor - Adversarial pattern recognition from bug bounty data.

Loads the bug bounty finetuning dataset and provides retrieval-based
context enrichment for agent prompts. This is for PATTERN RECOGNITION
and adversarial intuition -- NOT for replaying exploits.

The augmentor:
- Builds a keyword index by vulnerability type
- Retrieves relevant patterns matching current testing context
- Injects formatted reference material into agent prompts
- Explicitly instructs the model to adapt, not copy
"""

import json
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class KnowledgeAugmentor:
    """Retrieval-based knowledge augmentation from bug bounty dataset."""

    # Vulnerability type keyword mappings
    VULN_KEYWORDS = {
        'xss': ['xss', 'cross-site scripting', 'reflected xss', 'stored xss', 'dom xss',
                 'script injection', 'html injection'],
        'sqli': ['sql injection', 'sqli', 'union select', 'blind sql', 'error-based sql',
                 'time-based sql', 'second-order sql'],
        'ssrf': ['ssrf', 'server-side request forgery', 'internal service'],
        'idor': ['idor', 'insecure direct object', 'broken object level',
                 'bola', 'horizontal privilege'],
        'rce': ['rce', 'remote code execution', 'command injection', 'os command',
                'code execution', 'shell injection'],
        'lfi': ['lfi', 'local file inclusion', 'path traversal', 'directory traversal',
                'file read', 'file disclosure'],
        'auth_bypass': ['authentication bypass', 'broken authentication', 'auth bypass',
                        'session fixation', 'jwt', 'token manipulation'],
        'csrf': ['csrf', 'cross-site request forgery', 'state-changing'],
        'open_redirect': ['open redirect', 'url redirect', 'redirect vulnerability'],
        'xxe': ['xxe', 'xml external entity', 'xml injection'],
        'ssti': ['ssti', 'server-side template injection', 'template injection'],
        'race_condition': ['race condition', 'toctou', 'concurrency'],
        'graphql': ['graphql', 'introspection', 'batching attack'],
        'api': ['api', 'rest api', 'broken api', 'api key', 'rate limiting'],
        'deserialization': ['deserialization', 'insecure deserialization', 'pickle',
                           'object injection'],
        'upload': ['file upload', 'unrestricted upload', 'web shell', 'upload bypass'],
        'cors': ['cors', 'cross-origin', 'origin validation'],
        'subdomain_takeover': ['subdomain takeover', 'dangling dns', 'cname'],
        'information_disclosure': ['information disclosure', 'sensitive data', 'data exposure',
                                   'directory listing', 'source code disclosure'],
    }

    def __init__(self, dataset_path: str = "models/bug-bounty/bugbounty_finetuning_dataset.json",
                 max_patterns: int = 3):
        self.dataset_path = Path(dataset_path)
        self.max_patterns = max_patterns
        self.entries: List[Dict] = []
        self.index: Dict[str, List[int]] = {}  # vuln_type -> list of entry indices
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy load and index the dataset on first use."""
        if self._loaded:
            return

        if not self.dataset_path.exists():
            logger.warning(f"Bug bounty dataset not found: {self.dataset_path}")
            self._loaded = True
            return

        try:
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                self.entries = json.load(f)
            logger.info(f"Loaded {len(self.entries)} entries from bug bounty dataset")
            self._build_index()
        except Exception as e:
            logger.error(f"Failed to load bug bounty dataset: {e}")

        self._loaded = True

    def _build_index(self):
        """Build keyword index over the dataset entries."""
        for i, entry in enumerate(self.entries):
            text = (
                entry.get('instruction', '') + ' ' +
                entry.get('input', '') + ' ' +
                entry.get('output', '')
            ).lower()

            for vuln_type, keywords in self.VULN_KEYWORDS.items():
                for kw in keywords:
                    if kw in text:
                        self.index.setdefault(vuln_type, []).append(i)
                        break  # One match per vuln_type per entry

        indexed_types = {k: len(v) for k, v in self.index.items()}
        logger.info(f"Knowledge index built: {indexed_types}")

    def get_relevant_patterns(self, vulnerability_type: str,
                               technologies: Optional[List[str]] = None,
                               max_entries: Optional[int] = None) -> str:
        """Retrieve relevant bug bounty patterns for context enrichment.

        Args:
            vulnerability_type: Type of vulnerability being tested (e.g., 'xss', 'sqli')
            technologies: Optional list of detected technologies for relevance boosting
            max_entries: Override default max patterns count

        Returns:
            Formatted string for injection into LLM prompts as cognitive augmentation.
            Returns empty string if no relevant patterns found.
        """
        self._ensure_loaded()

        limit = max_entries or self.max_patterns
        vuln_key = vulnerability_type.lower().replace(' ', '_').replace('-', '_')

        # Try exact match first, then partial
        candidates = self.index.get(vuln_key, [])
        if not candidates:
            # Try partial matching
            for key, indices in self.index.items():
                if vuln_key in key or key in vuln_key:
                    candidates = indices
                    break

        if not candidates:
            return ""

        # Deduplicate
        candidates = list(dict.fromkeys(candidates))

        # Score by technology relevance if technologies provided
        if technologies:
            scored = []
            for idx in candidates:
                entry = self.entries[idx]
                text = (entry.get('output', '') + ' ' + entry.get('instruction', '')).lower()
                tech_score = sum(1 for t in technologies if t.lower() in text)
                scored.append((tech_score, idx))
            scored.sort(key=lambda x: x[0], reverse=True)
            candidates = [idx for _, idx in scored]

        selected = candidates[:limit]

        # Build augmentation context
        augmentation = (
            "\n\n=== ADVERSARIAL PATTERN CONTEXT (Bug Bounty Knowledge) ===\n"
            "These are REFERENCE PATTERNS for understanding attack vectors and methodology.\n"
            "ADAPT the approach to the current target. Do NOT replay exact exploits.\n"
            "Use these as cognitive anchors for creative hypothesis generation.\n\n"
        )

        for i, idx in enumerate(selected, 1):
            entry = self.entries[idx]
            instruction = entry.get('instruction', '')[:300]
            output = entry.get('output', '')

            # Extract methodology-relevant sections, truncate for context budget
            methodology = self._extract_methodology(output, max_chars=1500)

            augmentation += f"--- Pattern {i} ---\n"
            augmentation += f"Context: {instruction}\n"
            augmentation += f"Methodology:\n{methodology}\n\n"

        augmentation += "=== END ADVERSARIAL PATTERN CONTEXT ===\n"
        return augmentation

    def _extract_methodology(self, text: str, max_chars: int = 1500) -> str:
        """Extract the most methodology-relevant portion of a writeup."""
        # Look for methodology/steps/approach sections
        markers = ['### steps', '### methodology', '### approach', '### exploitation',
                    '## steps', '## methodology', '## approach', '## exploitation',
                    'steps to reproduce', 'reproduction steps', 'proof of concept']

        text_lower = text.lower()
        for marker in markers:
            idx = text_lower.find(marker)
            if idx != -1:
                return text[idx:idx + max_chars]

        # Fall back to first max_chars of the output
        return text[:max_chars]

    def get_available_types(self) -> List[str]:
        """Return list of vulnerability types that have indexed entries."""
        self._ensure_loaded()
        return sorted(self.index.keys())

    def get_entry_count(self, vulnerability_type: str) -> int:
        """Return count of indexed entries for a vulnerability type."""
        self._ensure_loaded()
        vuln_key = vulnerability_type.lower().replace(' ', '_').replace('-', '_')
        return len(self.index.get(vuln_key, []))
