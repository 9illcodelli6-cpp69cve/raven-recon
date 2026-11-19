# Local AI in RAVEN Recon

RAVEN works without any AI. When you want AI features you have three options:

| Option | Chat | Agent | Cost | Quality |
|---|---|---|---|---|
| **Claude** (Anthropic API) — recommended | ✅ | ✅ | pay per use (your key) | best |
| **Your own local model via Ollama** | ✅ | — | free, offline | depends on the model you choose |
| **RAVEN-Sec 0.5B** (advanced, built-in) | ✅ | ✅ | free, offline, CPU | limited — see below |

The local models are **off by default** in public builds.

## 1. Claude

RAVEN → **Settings → Claude (Anthropic API)** → paste your key → **Save & test**. See the
README for budgets and safety.

## 2. Your own local model through Ollama (chat)

```bash
# Linux:  curl -fsSL https://ollama.com/install.sh | sh     (or see https://ollama.com/download)
# Windows: winget install Ollama.Ollama
ollama pull qwen2.5-coder:7b          # or any model your machine can run
```
RAVEN → **Settings → Optional external provider (Ollama)** → enable it → model name
`qwen2.5-coder:7b` (leave empty to use the first installed model) → URL
`http://localhost:11434` → **Save**. AI Chat now answers with that model, fully offline.
Bigger models answer better; 7B–14B coder models run on most laptops with 16 GB RAM.

## 3. RAVEN-Sec 0.5B (advanced)

A LoRA fine-tune of **Qwen2.5-Coder-0.5B-Instruct** (Apache-2.0) with a local knowledge base
built from MITRE CWE/CAPEC/ATT&CK, OWASP WSTG and Cheat Sheets, and PayloadsAllTheThings.
It runs on a CPU without internet. Be realistic: a 0.5B model makes mistakes and invents
details; RAVEN therefore shows the **verbatim passages from the trusted sources first** and
labels the model's own summary. Measured on RAVEN's pentest benchmark
(`python -m raven.sec_ai.pentest_bench`) the composed answers score ≈0.70 (Claude is far
stronger).

```bash
# 1. local AI packages (CPU)
.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install -r requirements-ai.txt

# 2. where RAVEN keeps AI data
AI="${RAVEN_DATA_DIR:-$HOME/.local/share/raven-recon}/ai"; mkdir -p "$AI/corpus/raw"

# 3. base model (~1 GB)
.venv/bin/python -c "import os; from huggingface_hub import snapshot_download; \
snapshot_download('Qwen/Qwen2.5-Coder-0.5B-Instruct', local_dir=os.path.join('$AI', 'qwen2.5-coder-0.5b-instruct'))"

# 4. trusted sources for the knowledge base
cd "$AI/corpus/raw"
curl -fLO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip -o cwec_latest.xml.zip
curl -fL -o capec.xml https://capec.mitre.org/data/xml/capec_latest.xml
curl -fLO https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
git clone --depth 1 https://github.com/OWASP/wstg.git
git clone --depth 1 https://github.com/OWASP/CheatSheetSeries.git
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
cd -

# 5. build the knowledge base
.venv/bin/python -c "from raven.sec_ai import kb; print(kb.build())"

# 6. turn it on (Linux: put this in ~/.zshrc / ~/.bashrc;  Windows: setx RAVEN_LOCAL_AI 1)
export RAVEN_LOCAL_AI=1
```

Optional fine-tune (several hours on a CPU, resumable):
```bash
.venv/bin/python -m raven.sec_ai.dataset --subset 3000 --fit-len 768
.venv/bin/python -m raven.sec_ai.train_lora --data "$AI/dataset/train_3k.jsonl" --max-len 768
.venv/bin/python -m raven.sec_ai.evaluate          # held-out loss + tool-protocol compliance
.venv/bin/python -m raven.sec_ai.pentest_bench     # pentest benchmark: tuned vs base
```

Without the fine-tune, RAVEN-Sec uses the base model. Licences of the downloaded data:
MITRE terms of use, OWASP CC BY-SA 4.0, PayloadsAllTheThings MIT, Qwen Apache-2.0.
