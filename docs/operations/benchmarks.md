# Mitig8it Model Benchmarks

Benchmark dataset for evaluating LLM models on security vulnerability detection. Use it to compare candidate models before integrating them into the Mitig8it analysis pipeline.

## Structure

```
benchmarks/
├── dataset/
│   ├── true_positives/    # Code with known vulnerabilities
│   │   ├── python.json
│   │   ├── javascript.json
│   │   ├── java.json
│   │   └── go.json
│   └── true_negatives/    # Safe code that looks suspicious
│       ├── python.json
│       ├── javascript.json
│       ├── java.json
│       └── go.json
├── eval.py                # Evaluation script
└── results/               # Generated results (gitignored)
```

## Dataset

- **24 true positives**: code with confirmed vulnerabilities, labeled with CWE and severity
- **15 true negatives**: safe code that naive scanners might flag (parameterized queries, safe loaders, etc.)
- Covers: Python, JavaScript/TypeScript, Java, Go
- Derived from Mitig8it's existing regex and OpenGrep rule sets

## Running

```bash
# Install dependency
pip install anthropic openai

# Run against an Anthropic model
export ANTHROPIC_API_KEY=sk-...
python benchmarks/eval.py --provider anthropic --model claude-sonnet-4-6
python benchmarks/eval.py --provider anthropic --model claude-haiku-4-5-20251001
python benchmarks/eval.py --provider anthropic --model claude-opus-4-6

# Run against an OpenAI model
export OPENAI_API_KEY=sk-...
python benchmarks/eval.py --provider openai --model gpt-4o-mini

# Run multiple OpenAI models
python benchmarks/eval.py --provider openai --models gpt-4o-mini,gpt-4o,gpt-5

# Run all supported models
python benchmarks/eval.py --all

# Limit samples for quick test
python benchmarks/eval.py --provider openai --model gpt-4o-mini --samples 5
```

## Metrics

The eval script measures:
- **Precision**: of flagged code, how much is actually vulnerable
- **Recall**: of all vulnerabilities, how many were caught
- **F1 Score**: harmonic mean of precision and recall
- **Latency**: average response time per snippet
- **Cost**: total and per-scan API cost

## Adding samples

Add entries to the relevant JSON file under `benchmarks/dataset/true_positives/` or `benchmarks/dataset/true_negatives/`. Each entry needs:

```json
{
  "id": "tp-py-009",
  "rule_source": "which rule this tests",
  "language": "python",
  "cwe": "CWE-XXX",
  "owasp": "A03:2021",
  "severity": "high",
  "expected_verdict": "vulnerable",
  "description": "what the vulnerability is",
  "code": "the code snippet"
}
```

For true negatives, add a `why_safe` field explaining why the code is not vulnerable despite looking suspicious.
