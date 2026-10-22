"""
Grounded Response Generator for OWASP Top 10 RAG System.
Synthesizes verified answers with exact page citations, mitigations, and attack scenarios.
Supports both deterministic extraction (Zero Hallucination guaranteed) and optional LLM synthesis.
"""
from typing import Dict, Any, List
from rag_engine import OWASPRagEngine
from verifier import GroundingVerifier

class OWASPResponseGenerator:
    def __init__(self):
        self.rag_engine = OWASPRagEngine()
        self.verifier = GroundingVerifier(self.rag_engine)

    def process_query(self, query: str) -> Dict[str, Any]:
        """
        Executes end-to-end RAG pipeline:
        1. Retrieval (Hybrid BM25 + Semantic Matching)
        2. Grounded Synthesis
        3. Verification & Citation Validation
        """
        retrieved_results = self.rag_engine.retrieve(query, top_k=3)
        top_item, match_score = retrieved_results[0]

        # No relevant match found → return a sentinel response
        if top_item is None:
            return {"no_match": True, "query": query}

        secondary_matches = [
            {"id": item["id"], "name": item["name"], "name_ar": item["name_ar"], "score": score}
            for item, score in retrieved_results[1:]
            if item is not None
        ]

        # Extract raw page contents for citations
        raw_pages_dict = self.rag_engine.get_raw_pages(top_item["pages"])

        # Construct structured, strictly grounded response
        response_data = {
            "query": query,
            "match_confidence": match_score,
            "classification": {
                "id": top_item["id"],
                "rank": top_item["rank"],
                "name_en": top_item["name"],
                "name_ar": top_item["name_ar"],
                "category_badge": top_item.get("category_badge", "OWASP Top 10 (2025)"),
                "pages_display": top_item["page_display"]
            },
            "cited_pages": top_item["pages"],
            "description": {
                "summary_ar": top_item["short_summary_ar"],
                "full_ar": top_item["description_ar"],
                "full_en": top_item["description_en"],
                "types": top_item.get("types", [])
            },
            "key_risks": top_item.get("key_risks", []),
            "mitigations": top_item.get("mitigations", []),
            "scenarios": top_item.get("scenarios", []),
            "frameworks": top_item.get("frameworks", []),
            "exact_quotes": [
                {
                    "page": p,
                    "text": raw_pages_dict.get(p, "").strip()
                }
                for p in top_item["pages"] if raw_pages_dict.get(p)
            ],
            "secondary_matches": secondary_matches
        }

        # Run Verification Engine
        verification_report = self.verifier.verify(query, top_item, response_data)
        response_data["verification"] = verification_report

        return response_data
