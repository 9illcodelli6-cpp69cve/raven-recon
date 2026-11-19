"""RAVEN-Sec — the cybersecurity + coding model, its knowledge base and research agent.

Layout (all optional at runtime; nothing here is imported by the server until used):

    paths.py      where models / corpus / index live (RAVEN_AI_DIR, default <data>/ai)
    corpus.py     parsers for the trusted sources (MITRE CWE/CAPEC/ATT&CK, OWASP WSTG +
                  Cheat Sheets, PayloadsAllTheThings) -> uniform documents
    kb.py         local knowledge base: SQLite FTS5 (BM25) over those documents
    dataset.py    instruction + tool-use training examples built from the documents
    train_lora.py LoRA fine-tuning of the base model on CPU (resumable)
    llm.py        local inference provider (base or fine-tuned model)
    research.py   trusted-source web research (official APIs + allowlisted pages)
    agent.py      the research agent: tools, approval gate, sandboxed shell

Honesty: the model is a fine-tune of an open base model (Qwen2.5-Coder-0.5B-Instruct,
Apache-2.0), not trained from scratch; every answer is advisory and every action that
touches a target or the shell needs the researcher's approval.
"""
