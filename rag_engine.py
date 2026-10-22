"""
Hybrid RAG Engine for OWASP Top 10 for LLM Applications 2025.
Combines semantic matching, keyword BM25 retrieval, and bilingual (Arabic/English) query expansion.
"""
import json
import os
import re
from typing import List, Dict, Any, Tuple
from rank_bm25 import BM25Okapi

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TOP10_PATH = os.path.join(DATA_DIR, "owasp_top10_2025.json")
PAGES_PATH = os.path.join(DATA_DIR, "owasp_pages.json")

class OWASPRagEngine:
    def __init__(self):
        with open(TOP10_PATH, "r", encoding="utf-8") as f:
            self.top10_data: List[Dict[str, Any]] = json.load(f)

        with open(PAGES_PATH, "r", encoding="utf-8") as f:
            self.pages_data: Dict[str, str] = json.load(f)

        self._build_search_index()

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenizer for English and Arabic keywords."""
        text = text.lower()
        # Clean punctuation but preserve words and hyphenated terms
        words = re.findall(r"[\w\u0600-\u06FF]+", text)
        return words

    def _build_search_index(self):
        """Builds BM25 index and chunked document store for retrieval."""
        self.corpus = []
        self.doc_map = []

        for item in self.top10_data:
            # Combine all rich textual fields for comprehensive retrieval
            content_blocks = [
                f"{item['id']} {item['name']} {item['name_ar']}",
                item['short_summary_ar'],
                item['short_summary_en'],
                item['description_ar'],
                item['description_en'],
                " ".join(item['key_risks']),
                " ".join([f"{m['title']}: {m['detail']}" for m in item['mitigations']]),
                " ".join(item['scenarios']),
                " ".join(item.get('keywords', [])),
                " ".join(item.get('frameworks', []))
            ]
            full_text = " \n ".join(content_blocks)
            self.corpus.append(self._tokenize(full_text))
            self.doc_map.append(item)

        self.bm25 = BM25Okapi(self.corpus)

        # Dictionary for direct code lookup (e.g. LLM01, LLM02, 1, 2)
        self.code_lookup = {}
        for item in self.top10_data:
            self.code_lookup[item['id'].lower()] = item
            self.code_lookup[f"llm{item['rank']:02d}"] = item
            self.code_lookup[str(item['rank'])] = item
            self.code_lookup[item['name'].lower()] = item
            self.code_lookup[item['name_ar']] = item

    def retrieve(self, query: str, top_k: int = 3) -> List[Tuple[Dict[str, Any], float]]:
        """
        Retrieves the most relevant OWASP Top 10 vulnerabilities for a query or scenario.
        Returns list of (item, score) sorted by relevance.
        """
        query_clean = query.strip()
        query_lower = query_clean.lower()

        # Check for direct ID match (e.g. 'LLM01', 'LLM05', 'LLM10:2025', '1')
        # Sort codes by length descending so longer/more specific matches win first
        for code in sorted(self.code_lookup.keys(), key=len, reverse=True):
            if code in query_lower:
                return [(self.code_lookup[code], 1.0)]

        # Arabic and English synonym boosting dictionary
        boost_map = {
            "prompt injection": "LLM01:2025",
            "حقن": "LLM01:2025",
            "توجيه": "LLM01:2025",
            "jailbreak": "LLM01:2025",
            "جيلبريك": "LLM01:2025",
            "sensitive": "LLM02:2025",
            "pii": "LLM02:2025",
            "سرية": "LLM02:2025",
            "خصوصية": "LLM02:2025",
            "تسريب بيانات": "LLM02:2025",
            "هوية شخصية": "LLM02:2025",
            "supply chain": "LLM03:2025",
            "سلاسل إمداد": "LLM03:2025",
            "سلسلة إمداد": "LLM03:2025",
            "lora": "LLM03:2025",
            "hugging face": "LLM03:2025",
            "leftovers": "LLM03:2025",
            "cve-2023-4969": "LLM03:2025",
            "poisongpt": "LLM03:2025",
            "data poisoning": "LLM04:2025",
            "model poisoning": "LLM04:2025",
            "تسميم البيانات": "LLM04:2025",
            "تسميم النموذج": "LLM04:2025",
            "sleeper agent": "LLM04:2025",
            "عميل نائم": "LLM04:2025",
            "pickle": "LLM04:2025",
            "output handling": "LLM05:2025",
            "معالجة المخرجات": "LLM05:2025",
            "xss": "LLM05:2025",
            "rce": "LLM05:2025",
            "sql injection": "LLM05:2025",
            "حقن sql": "LLM05:2025",
            "تشغيل كود": "LLM05:2025",
            "agency": "LLM06:2025",
            "excessive agency": "LLM06:2025",
            "وكالة مفرطة": "LLM06:2025",
            "صلاحيات مفرطة": "LLM06:2025",
            "استقلالية": "LLM06:2025",
            "وكيل": "LLM06:2025",
            "agent": "LLM06:2025",
            "system prompt": "LLM07:2025",
            "موجه النظام": "LLM07:2025",
            "تسريب البرومبت": "LLM07:2025",
            "prompt leakage": "LLM07:2025",
            "vector": "LLM08:2025",
            "embedding": "LLM08:2025",
            "rag": "LLM08:2025",
            "متجهات": "LLM08:2025",
            "تضمين": "LLM08:2025",
            "نص أبيض": "LLM08:2025",
            "white text": "LLM08:2025",
            "multi-tenant": "LLM08:2025",
            "misinformation": "LLM09:2025",
            "معلومات مضللة": "LLM09:2025",
            "هلوسة": "LLM09:2025",
            "hallucination": "LLM09:2025",
            "air canada": "LLM09:2025",
            "طيران كندا": "LLM09:2025",
            "تزييف": "LLM09:2025",
            "consumption": "LLM10:2025",
            "unbounded": "LLM10:2025",
            "denial of wallet": "LLM10:2025",
            "dow": "LLM10:2025",
            "dos": "LLM10:2025",
            "استنزاف الميزانية": "LLM10:2025",
            "استهلاك الموارد": "LLM10:2025",
            "حرمان الخدمة": "LLM10:2025",
            "سرقة النموذج": "LLM10:2025"
        }

        # Tokenize query
        tokenized_query = self._tokenize(query_clean)
        if not tokenized_query:
            return [(None, 0.0)]

        # BM25 scores (raw — before boosts)
        scores = self.bm25.get_scores(tokenized_query)
        raw_max_score = max(scores)

        # Check if any keyword boost applies
        boost_hit = any(kw in query_lower for kw in boost_map)

        # If BM25 found nothing AND no boost keyword matched → unrecognized query
        # Also reject if all query tokens are very short (< 3 chars) — likely random/gibberish
        meaningful_tokens = [t for t in tokenized_query if len(t) >= 3]
        if raw_max_score < 0.45 and not boost_hit:
            return [(None, 0.0)]
        if raw_max_score < 0.5 and not boost_hit and len(meaningful_tokens) == 0:
            return [(None, 0.0)]

        # Apply keyword boosts
        adjusted_scores = list(scores)
        for i, item in enumerate(self.doc_map):
            item_id = item['id']
            for kw, target_id in boost_map.items():
                if kw in query_lower and target_id == item_id:
                    adjusted_scores[i] += 8.0

        # Rank results
        ranked_indices = sorted(range(len(adjusted_scores)), key=lambda i: adjusted_scores[i], reverse=True)
        max_score = max(adjusted_scores) if max(adjusted_scores) > 0 else 1.0

        results = []
        for idx in ranked_indices[:top_k]:
            normalized_score = min(1.0, adjusted_scores[idx] / max_score) if max_score > 0 else 0.5
            results.append((self.doc_map[idx], round(normalized_score, 3)))

        return results

    def get_raw_pages(self, page_numbers: List[int]) -> Dict[int, str]:
        """Returns the raw document text for the specified page numbers."""
        return {p: self.pages_data.get(str(p), "") for p in page_numbers}

    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Returns all 10 vulnerabilities."""
        return self.top10_data
