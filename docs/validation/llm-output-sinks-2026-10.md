# Language model output reaching a sink, October 2026

OWASP's Top 10 for LLM applications names improper output handling (LLM05) as the class where a
model's answer is used as code, a command, a query or markup without the checks the same value
would get if a user had typed it. A prompt the attacker can influence, directly or through a
document the model reads, then decides what reaches the sink. Before this change no rule in the
tree treated a model's answer as untrusted.

Seven taint rules are added, three for Python and four for JavaScript and TypeScript. All seven
post. This document records what they match, what they were measured on, and the remediation gate
added beside them.

## The rules

The source is the return value of a model client call in the same function. Attribute and index
access propagate, so `response.choices[0].message.content`, `message.content[0].text`,
`.output_text` and a destructured `{ text }` all carry the taint.

| Source | Python | JavaScript / TypeScript |
| --- | --- | --- |
| OpenAI chat completions | `$C.chat.completions.create(...)` | `$C.chat.completions.create(...)` |
| OpenAI responses | `$C.responses.create(...)` | `$C.responses.create(...)` |
| Anthropic messages | `$C.messages.create(...)` | `$C.messages.create(...)` |
| Google Gemini | `$C.generate_content(...)` | `$M.generateContent(...)` |
| Other | `litellm.completion(...)` | AI SDK `generateText(...)` |

| Rule | Sink | Internal type | Family |
| --- | --- | --- | --- |
| `cwe-95.py-llm-output-code-execution` | `eval`, `exec` | `dynamic_code_execution` | `code_injection_eval` |
| `cwe-78.py-llm-output-shell` | `os.system`, `os.popen`, `subprocess.*(..., shell=True)` | `command_injection` | none declared |
| `cwe-89.py-llm-output-sql` | the query argument of `.execute(...)` | `sql_injection` | `sql_parameterization` |
| `cwe-95.js-llm-output-code-execution` | `eval`, `new Function` | `dynamic_code_execution` | `code_injection_eval` |
| `cwe-78.js-llm-output-shell` | `exec`, `execSync`, `child_process.exec*` | `command_injection` | none declared |
| `cwe-79.js-llm-output-html` | `innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML` | `cross_site_scripting` | none |
| `cwe-89.js-llm-output-sql` | the query argument of `.query(...)` | `sql_injection` | `sql_parameterization` |

The JavaScript shell rule names the `child_process` receiver, as `cwe-78.js-exec-interpolated`
does, because `$X.exec` is also `RegExp.prototype.exec` and model output is often matched
against a regular expression. The SQL rules focus on the query argument, so a model answer passed
as a bound parameter is silent.

## Measurement on real code

Twelve open-source LLM applications were cloned at depth 1 and scanned as text with the seven
rules. Nothing was installed or executed.

| Repository | Commit | Source files |
| --- | --- | ---: |
| `danny-avila/LibreChat` | `e081b566a42d` | 6193 |
| `joaomdmoura/crewAI` | `3da49f872b15` | 1426 |
| `langchain-ai/langchain` | `4fe944a58189` | 2639 |
| `lobehub/lobe-chat` | `a29809c69b3c` | 17381 |
| `mckaywrigley/chatbot-ui` | `81328b61d2a4` | 261 |
| `microsoft/autogen` | `004749e6b710` | 680 |
| `Mintplex-Labs/anything-llm` | `d7d68e75c422` | 1237 |
| `open-webui/open-webui` | `91ea4e3421d1` | 424 |
| `openinterpreter/open-interpreter` | `ac1fcc8fe57a` | 978 |
| `run-llama/llama_index` | `619d74664e84` | 3780 |
| `Significant-Gravitas/AutoGPT` | `8d4a965b7bbc` | 6250 |
| `vercel/ai-chatbot` | `c2f8235e1f3e` | 154 |

Opengrep reported 38,098 files scanned. 159 non-test files call one of the source APIs.

**The rules produced zero findings.** That is no false positives on the code most likely to
contain the source, which is the precision claim the posting decision rests on. It is also no
true positives, and the reason matters. In a mature application the model call lives in a
provider class and the sink lives in a tool runner several calls away. open-interpreter executes
model-written code by design, and it does so through exactly that kind of indirection. The rules
are intraprocedural, so they see the shape a pull request adding a first LLM feature tends to
have: the call and the sink in one function. That is the shape this product reviews.

The posting decision follows `tier2-coverage-2026-09.md`, where 87 rules post on zero findings
because their pattern is a sink with a clear taxonomy. These rules require a source and a sink in
one flow, so they are narrower than those.

## Fixtures

`benchmarks/tier2-precision/cases.json` gains one true-positive fixture per rule and four cases
that must stay silent:

- A model answer passed to `cursor.execute` as a bound parameter.
- A model answer matched with `/\d+/.exec(text)`.
- A model answer written to `textContent`.
- A constant `exec("import json")` in a function that also calls the model.

The last one is there to show the rules follow the value, not proximity to a model call.

## The remediation gate

`rule_family()` in the remediation service maps CWE-78 to `command_arguments`, whose repair is an
argument list with the untrusted value as its own element. For a command the model wrote in full,
that rewrite is `subprocess.run([answer])`. It would pass the argument-list proof and still run
whatever program the model named. The new gate `model_authored_command` refuses a
`command_arguments` repair for any `*-llm-output-shell` finding, with a message saying the fix is
an allowlist of commands. The finding is still posted.

The other families were checked on the fixtures:

- **Eval:** templates refuse `exec(code)` with `eval_argument_not_a_parameter`, and the agent
  abstains with `eval_semantics_unknown` unless the code needs only a literal.
- **Python SQL:** the gate abstains when no driver is imported in the file.
- **JavaScript SQL:** the template parameterizes a quoted value, as it does for any other source.

## What is not covered

- **Flows across functions.** This is the main limit, as described above.
- **Agent frameworks:** LangChain chains, LlamaIndex query engines and CrewAI agents. Their
  method names (`invoke`, `run`, `query`) are too generic to be a source without type
  information.
- **Over-permissioned agent tools and MCP servers.** A tool that exposes a shell or file write is
  a configuration question, not a data flow, and needs its own rules.
- **Prompt injection into the model.** `llm.prompt.injection` in tier 1 is the only signal there.

## Reproducing it

```sh
TREES=/tmp/llm-trees   # an empty directory outside the repository
for r in danny-avila/LibreChat joaomdmoura/crewAI langchain-ai/langchain lobehub/lobe-chat \
         mckaywrigley/chatbot-ui microsoft/autogen Mintplex-Labs/anything-llm \
         open-webui/open-webui openinterpreter/open-interpreter run-llama/llama_index \
         Significant-Gravitas/AutoGPT vercel/ai-chatbot; do
  git clone -q --depth 1 https://github.com/$r "$TREES/$(echo $r | tr / _)"
done
# git -C <tree> checkout <commit> to pin each tree to the commits in the table
opengrep scan --config services/analysis-service/src/opengrep_rules/python_coverage.yml \
  --config services/analysis-service/src/opengrep_rules/javascript_coverage.yml \
  --exclude node_modules --json "$TREES" | jq '[.results[] | select(.check_id | test("llm-output"))] | length'
```
