import os
import re
import math
from typing import List, Dict, Any, Tuple, Optional
from openai import OpenAI


def citation_label(metadata: Dict[str, Any]) -> str:
    """Return the stable citation token exposed to the model and UI."""
    if metadata.get("source") == "CISA_CSAF":
        return metadata.get("advisory_id", "CISA_CSAF")
    if metadata.get("source") == "CISA_VULNRICHMENT":
        return metadata.get("cve", "CISA_VULNRICHMENT")
    if metadata.get("source") == "MITRE_ATTACK_ICS":
        return metadata.get("attack_id", "MITRE_ATTACK_ICS")
    if metadata.get("source") == "USER_UPLOAD":
        return metadata.get("filename", "USER_UPLOAD")
    return metadata.get("source", "UNKNOWN_SOURCE")


def extract_cited_chunks(answer: str, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Resolve source-name citations, while accepting legacy Index citations."""
    cited: List[Dict[str, Any]] = []
    seen_labels = set()
    tokens = {token.strip().lower() for token in re.findall(r"\[([^\[\]]+)\]", answer)}
    for index, chunk in enumerate(chunks, start=1):
        label = citation_label(chunk.get("metadata", {}))
        normalized_label = label.lower()
        if (normalized_label in tokens or f"index {index}" in tokens) and normalized_label not in seen_labels:
            cited.append(chunk)
            seen_labels.add(normalized_label)
    return cited

def format_retrieved_chunks(chunks: List[Dict[str, Any]]) -> str:
    """
    Format a list of retrieved chunks into a clear text block for the LLM context.
    Each chunk is prepended with its index and metadata citation headers.
    """
    formatted_docs = []
    for idx, chunk in enumerate(chunks):
        meta = chunk.get("metadata", {})
        source = meta.get("source", "Unknown Source")
        
        # Format citation header depending on the source type (CSAF vs NIST PDFs)
        if source == "CISA_CSAF":
            citation_header = (
                f"CISA ICS Advisory {meta.get('advisory_id', 'Unknown')} | "
                f"Vendor: {meta.get('vendor', 'Unknown')} | "
                f"Products: {meta.get('products', 'Unknown')} | "
                f"Date: {meta.get('date', 'Unknown')} | "
                f"Severity: {meta.get('severity', 'Unknown')}"
            )
        elif source == "CISA_VULNRICHMENT":
            citation_header = (
                f"CVE: {meta.get('cve', 'Unknown')} | "
                f"Vendor: {meta.get('vendor', 'Unknown')} | "
                f"Products: {meta.get('products', 'Unknown')} | "
                f"Severity: {meta.get('severity', 'Unknown')} | "
                f"KEV: {meta.get('known_exploited', False)}"
            )
        elif source == "MITRE_ATTACK_ICS":
            citation_header = (
                f"ATT&CK ID: {meta.get('attack_id', 'Unknown')} | "
                f"Type: {meta.get('entity_type', 'Unknown')} | "
                f"Name: {meta.get('title', 'Unknown')} | "
                f"Version: {meta.get('version', 'Unknown')}"
            )
        else:
            citation_header = (
                f"Document Source: {source} | "
                f"Chapter: {meta.get('chapter', 'Unknown')} | "
                f"Section: {meta.get('section', 'Unknown')} | "
                f"Pages: {meta.get('page_start', '?')}-{meta.get('page_end', '?')}"
            )
            
        label = citation_label(meta)
        formatted_docs.append(f"--- Citation: [{label}] | {citation_header} ---\n{chunk['text']}")
    return "\n\n".join(formatted_docs)

def sigmoid(x: float) -> float:
    """
    Map logit score to 0-1 range using sigmoid function.
    """
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0

class SecureOpsGenerator:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "deepseek-chat",
        low_confidence_threshold: float = 0.0  # Cross-Encoder ms-marco-MiniLM logit threshold; scores below 0.0 indicate poor relevance and trigger honest refusal
    ):
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.model_name = model_name
        self.low_confidence_threshold = low_confidence_threshold
        
        if self.api_key:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
                timeout=60.0,
                max_retries=0,
            )
            self._has_client = True
        else:
            self._has_client = False

    def generate_answer(
        self,
        query: str,
        retrieved_chunks: List[Dict[str, Any]]
    ) -> Tuple[str, float, List[Dict[str, Any]]]:
        """
        Generates an answer using the DeepSeek API based on retrieved chunks.
        Returns: Tuple of (answer_text, confidence_score, cited_sources)
        """
        if not retrieved_chunks:
            return "I don't have enough information in my knowledge base to answer this.", 0.0, []
            
        top_score = retrieved_chunks[0].get("rerank_score", 0.0)
        confidence = sigmoid(top_score)
        
        if top_score < self.low_confidence_threshold:
            return "I don't have enough information in my knowledge base to answer this.", confidence, []

        system_instruction = (
            "You are SecureOps Assistant, an AI expert in industrial control systems (ICS) and operational technology (OT) cybersecurity.\n"
            "Your task is to answer the user's question relying ONLY on the provided Document Chunks.\n\n"
            "Guidelines:\n"
            "1. Reason privately; never reveal hidden chain-of-thought.\n"
            "2. Return only the user-facing final answer. Do not include <thinking>, <answer>, or other wrapper tags.\n"
            "3. If the provided Document Chunks do not contain enough information, "
            "or if the question is out of scope/malicious, your <answer> block MUST contain exactly: \"I don't have enough information in my knowledge base to answer this.\"\n"
            "4. Do not use external knowledge or make up answers. Keep responses completely grounded in the context.\n"
            "5. Cite the exact token shown in each chunk header (e.g. [ICSA-26-029-02], [CVE-2024-1234], or [NIST_CSF_2.0]). Do not use abstract indices.\n"
            "6. At the end of the answer, list the sources you cited under a \"Sources Cited:\" heading.\n"
            "7. Express version comparisons in words (for example, 'earlier than V5.250') instead of raw angle-bracket notation.\n"
        )
        
        formatted_context = format_retrieved_chunks(retrieved_chunks)
        user_prompt = f"Document Chunks:\n\n{formatted_context}\n\nQuestion: {query}\n\nResponse:"
        
        if not self._has_client:
            warning_msg = (
                "[System Note: DeepSeek API Key not configured. Please set the DEEPSEEK_API_KEY environment variable. "
                f"Retrieved {len(retrieved_chunks)} relevant chunks with {confidence:.1%} confidence.]"
            )
            return warning_msg, confidence, retrieved_chunks

        try:
            import time
            max_retries = 3
            full_text = ""
            for attempt in range(max_retries):
                try:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": system_instruction},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=0.1
                    )
                    # Handle both standard content and potential deepseek-reasoner reasoning_content
                    msg = response.choices[0].message
                    reasoning = getattr(msg, "reasoning_content", None)
                    content = msg.content or ""
                    
                    if reasoning:
                        full_text = f"<thinking>\n{reasoning}\n</thinking>\n{content}"
                    else:
                        full_text = content
                    break
                except Exception as e:
                    if "429" in str(e) or "quota" in str(e).lower() or "exhausted" in str(e).lower():
                        if attempt < max_retries - 1:
                            print(f"[System] API Rate limit hit. Pausing 20s (Attempt {attempt+1}/{max_retries})...")
                            time.sleep(20)
                            continue
                    raise e
            
            # Parse the <answer> block
            answer_match = re.search(r'<answer>(.*?)</answer>', full_text, re.DOTALL)
            if answer_match:
                answer_text = answer_match.group(1).strip()
            else:
                answer_text = re.sub(r'<(?:thinking|think)>.*?</(?:thinking|think)>', '', full_text, flags=re.DOTALL).strip()
                
            if "I don't have enough information" in answer_text:
                return answer_text, confidence, []
            
            # Parse cited sources
            cited_sources = extract_cited_chunks(answer_text, retrieved_chunks)
            
            # Self-Correction
            if not self._critique_answer(query, answer_text, formatted_context):
                return "I don't have enough information in my knowledge base to answer this.", confidence, []
                    
            return answer_text, confidence, cited_sources
            
        except Exception as e:
            return f"Error communicating with DeepSeek API: {str(e)}", confidence, []

    def generate_answer_stream(
        self,
        query: str,
        retrieved_chunks: List[Dict[str, Any]]
    ):
        """
        Generates an answer using the DeepSeek API via Streaming.
        Yields tokens. At the end, yields __CRITIQUE_FAIL__ or __METADATA__:{json_str}.
        """
        import json
        if not retrieved_chunks:
            yield "I don't have enough information in my knowledge base to answer this."
            return
            
        top_score = retrieved_chunks[0].get("rerank_score", 0.0)
        confidence = sigmoid(top_score)
        
        if top_score < self.low_confidence_threshold:
            yield "I don't have enough information in my knowledge base to answer this."
            return

        system_instruction = (
            "You are SecureOps Assistant, an AI expert in industrial control systems (ICS) and operational technology (OT) cybersecurity.\n"
            "Your task is to answer the user's question relying ONLY on the provided Document Chunks.\n\n"
            "Guidelines:\n"
            "1. Reason privately; never reveal hidden chain-of-thought.\n"
            "2. Return only the user-facing final answer. Do not include <thinking>, <answer>, or other wrapper tags.\n"
            "3. If the provided Document Chunks do not contain enough information, "
            "or if the question is out of scope/malicious, your <answer> block MUST contain exactly: \"I don't have enough information in my knowledge base to answer this.\"\n"
            "4. Do not use external knowledge or make up answers. Keep responses completely grounded in the context.\n"
            "5. Cite the exact token shown in each chunk header (e.g. [ICSA-26-029-02], [CVE-2024-1234], or [NIST_CSF_2.0]). Do not use abstract indices.\n"
            "6. At the end of the answer, list the sources you cited under a \"Sources Cited:\" heading.\n"
            "7. Express version comparisons in words (for example, 'earlier than V5.250') instead of raw angle-bracket notation.\n"
        )
        
        formatted_context = format_retrieved_chunks(retrieved_chunks)
        user_prompt = f"Document Chunks:\n\n{formatted_context}\n\nQuestion: {query}\n\nResponse:"
        
        if not self._has_client:
            warning_msg = (
                "[System Note: DeepSeek API Key not configured. Please set the DEEPSEEK_API_KEY environment variable. "
                f"Retrieved {len(retrieved_chunks)} relevant chunks with {confidence:.1%} confidence.]"
            )
            yield warning_msg
            return

        try:
            import time
            max_retries = 3
            full_text = ""
            
            for attempt in range(max_retries):
                try:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": system_instruction},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=0.1,
                        stream=True
                    )
                    
                    _is_reasoning = False
                    for chunk in response:
                        delta = chunk.choices[0].delta
                        
                        # Handle reasoning_content from DeepSeek-R1 if present
                        reasoning = getattr(delta, "reasoning_content", None)
                        if reasoning:
                            if not _is_reasoning:
                                yield "<thinking>\n"
                                full_text += "<thinking>\n"
                                _is_reasoning = True
                            yield reasoning
                            full_text += reasoning
                            
                        # Handle standard content
                        content = getattr(delta, "content", None)
                        if content:
                            if _is_reasoning:
                                yield "\n</thinking>\n"
                                full_text += "\n</thinking>\n"
                                _is_reasoning = False
                            yield content
                            full_text += content
                    
                    break # Success, exit retry loop
                    
                except Exception as e:
                    if "429" in str(e) or "quota" in str(e).lower() or "exhausted" in str(e).lower():
                        if attempt < max_retries - 1:
                            yield f"\n\n[System] DeepSeek API Rate limit hit. Pausing for 20 seconds (Attempt {attempt+1}/{max_retries})...\n\n"
                            time.sleep(20)
                            continue
                    raise e
                
            # Post-generation logic
            answer_match = re.search(r'<answer>(.*?)</answer>', full_text, re.DOTALL)
            if answer_match:
                answer_text = answer_match.group(1).strip()
            else:
                answer_text = re.sub(r'<(?:thinking|think)>.*?</(?:thinking|think)>', '', full_text, flags=re.DOTALL).strip()
                
            if "I don't have enough information" in answer_text:
                return # We streamed it, just stop.
                
            # Auto-Critique
            if not self._critique_answer(query, answer_text, formatted_context):
                yield "\n\n__CRITIQUE_FAIL__"
                return
                
            # Parse citations
            cited_sources = []
            for chunk in extract_cited_chunks(answer_text, retrieved_chunks):
                src_meta = chunk.get("metadata", {})
                cited_sources.append({
                    "label": citation_label(src_meta),
                    "source": src_meta.get("source", "Unknown"),
                    "metadata": src_meta,
                })
            
            metadata = {
                "confidence": confidence,
                "cited": cited_sources
            }
            yield f"\n\n__METADATA__:{json.dumps(metadata)}"
            
        except Exception as e:
            yield f"\n\nError communicating with DeepSeek API: {str(e)}"

    def _critique_answer(self, query: str, answer: str, context: str) -> bool:
        """
        Critiques the generated answer against the context.
        Returns True if the answer is factual and supported, False if it hallucinates.
        """
        if not self._has_client:
            return True
            
        critique_prompt = (
            "You are an objective auditor. You must verify if the provided Answer is completely supported by the Context.\n\n"
            f"Context:\n{context}\n\n"
            f"Question:\n{query}\n\n"
            f"Answer to evaluate:\n{answer}\n\n"
            "Does the Answer contain any facts or claims not explicitly stated in the Context? "
            "Is the Answer attempting to guess or hallucinate?\n"
            "Respond with exactly one word: PASS if it is perfectly grounded, or FAIL if it contains unsupported claims."
        )
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a strict auditor."},
                        {"role": "user", "content": critique_prompt}
                    ],
                    temperature=0.0
                )
                if "FAIL" in (response.choices[0].message.content or "").upper():
                    return False
                return True
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower() or "exhausted" in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(20)
                        continue
                return False
