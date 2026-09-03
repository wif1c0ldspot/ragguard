"""RAG Pipeline Security Scanner.

ragguard detects security vulnerabilities in Retrieval-Augmented Generation (RAG)
pipelines, including prompt injection via poisoned documents, metadata injection,
chunk-splitting exploits, cross-user contamination, and embedding manipulation.

Designed for the OWASP LLM Top 10 categories LLM06 (Insecure Output Handling)
and LLM07 (Training Data Poisoning).
"""