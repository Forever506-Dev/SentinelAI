"""
LLM Engine Service  —  with OSINT Tool-Calling Loop

Multi-provider LLM integration for threat analysis and investigation.
The investigate() method now:
  1. Receives DB-enriched context (agent profile, telemetry, alerts)
  2. Gives the LLM a system prompt listing available OSINT tools
  3. Parses the LLM response for tool_calls requests
  4. Executes requested tools (whois, nslookup, ip_lookup, http_check)
  5. Feeds results back and re-prompts  (max 3 rounds)
  6. Returns the final structured analysis

Supports: Ollama (primary), OpenAI, Anthropic.
"""

import json
import re
import structlog

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

try:
    from langchain_ollama import ChatOllama
except ImportError:
    try:
        from langchain_ollama import OllamaLLM as ChatOllama
    except ImportError:
        try:
            from langchain_community.chat_models import ChatOllama
        except ImportError:
            ChatOllama = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None

from app.core.config import settings
from app.services.osint_tools import execute_tool, TOOL_DESCRIPTIONS

logger = structlog.get_logger()

MAX_TOOL_ROUNDS = 3

# ─────────────────────────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────────────────────────

THREAT_ANALYSIS_SYSTEM_PROMPT = """You are SentinelAI, an expert cybersecurity threat analyst AI. You analyze endpoint
telemetry data, security alerts, and indicators of compromise (IOCs) with the precision
of a senior SOC analyst.

Your responsibilities:
1. Analyze security events and classify threat severity accurately
2. Map threats to the MITRE ATT&CK framework (tactics, techniques, sub-techniques)
3. Provide actionable remediation recommendations
4. Identify attack chains and lateral movement patterns
5. Correlate events across multiple endpoints
6. Assess confidence levels honestly - state uncertainty when appropriate

Response format: Always respond with structured JSON containing:
- analysis: Detailed threat analysis narrative
- severity: critical | high | medium | low | informational
- confidence: 0.0 to 1.0
- mitre_techniques: Array of MITRE ATT&CK technique IDs (e.g., T1059.001)
- recommendations: Array of actionable steps
- ioc_indicators: Any extracted IOCs (IPs, domains, hashes)
- kill_chain_phase: reconnaissance | weaponization | delivery | exploitation | installation | c2 | actions_on_objectives
"""

SHELL_ANALYSIS_SYSTEM_PROMPT = """You are SentinelAI, an expert cybersecurity analyst reviewing the output of a remote
command executed on a monitored endpoint. Your job is to analyze the output for:

1. **Security Issues**: Suspicious processes, unusual network connections, unauthorized users,
   malware indicators, persistence mechanisms, data exfiltration signs
2. **Vulnerabilities**: Outdated software with known CVEs, weak configurations, missing patches,
   exposed services
3. **Anomalies**: Anything unusual compared to a healthy baseline system
4. **MITRE ATT&CK Mapping**: Map any findings to relevant ATT&CK techniques
5. **Risk Assessment**: Overall risk level with evidence

## Response format (JSON):
- summary: One-paragraph executive summary of findings
- risk_level: critical | high | medium | low | clean
- findings: Array of objects, each with:
  - title: Short finding title
  - severity: critical | high | medium | low | informational
  - description: Detailed explanation with evidence from the output
  - mitre_technique: ATT&CK technique ID if applicable (e.g. T1059.001)
  - evidence: The specific line(s) from the output that triggered this finding
- recommendations: Array of actionable remediation steps
- mitre_techniques: Array of all ATT&CK technique IDs found
- confidence: 0.0 to 1.0

Be thorough but avoid false positives. If the output looks clean, say so clearly.
Always cite specific evidence from the command output."""

INVESTIGATION_SYSTEM_PROMPT = """You are SentinelAI, an AI-powered cybersecurity investigation assistant. You help
security analysts investigate threats using endpoint telemetry, alerts, and OSINT tools.

## Context Data
You will receive enriched context containing:
- **Agent profiles**: hostname, OS, IP, CPU/memory, software inventory
- **Recent alerts**: severity, MITRE techniques, detection source
- **Recent telemetry**: processes, network connections, file events

## OSINT Tools
You have access to these network lookup tools. To use them, include a "tool_calls"
array in your JSON response. Each tool call is an object with "tool" and "args":

{tool_descriptions}

### Example tool_calls:
```json
{{
  "analysis": "I need to look up the IP address to determine its origin...",
  "confidence": 0.3,
  "tool_calls": [
    {{"tool": "whois", "args": {{"target": "example.com"}}}},
    {{"tool": "ip_lookup", "args": {{"ip": "8.8.8.8"}}}},
    {{"tool": "nslookup", "args": {{"domain": "example.com", "record_type": "MX"}}}},
    {{"tool": "http_check", "args": {{"url": "https://example.com"}}}}
  ]
}}
```

## Rules
- If agent data is provided, USE IT — analyze the real telemetry, alerts, and system info
- When the context contains installed software, check for known vulnerable versions
- When the context contains processes, look for suspicious parent-child chains
- When the context contains network connections, identify unusual destinations
- If you need external data (WHOIS, DNS, IP geo, site status), use tool_calls
- Be specific, cite evidence, flag uncertainties
- Recommend MITRE ATT&CK techniques when relevant

## Response format (JSON):
- analysis: Your investigation findings (use the actual agent data provided)
- confidence: 0.0 to 1.0
- recommendations: Array of next steps
- mitre_techniques: Relevant ATT&CK technique IDs
- sources: What data sources informed your analysis
- tool_calls: (optional) Array of OSINT tool requests if you need more data
"""


class LLMEngine:
    """Multi-provider LLM engine with OSINT tool-calling."""

    def __init__(self) -> None:
        self.provider = settings.LLM_PROVIDER
        self.llm = self._initialize_llm()
        self.str_parser = StrOutputParser()

    def _initialize_llm(self):
        match self.provider:
            case "openai":
                if ChatOpenAI is None:
                    raise ImportError("langchain-openai not installed")
                return ChatOpenAI(
                    model=settings.OPENAI_MODEL,
                    api_key=settings.OPENAI_API_KEY,
                    temperature=0.1,
                    max_tokens=4096,
                )
            case "anthropic":
                if ChatAnthropic is None:
                    raise ImportError("langchain-anthropic not installed")
                return ChatAnthropic(
                    model=settings.ANTHROPIC_MODEL,
                    api_key=settings.ANTHROPIC_API_KEY,
                    temperature=0.1,
                    max_tokens=4096,
                )
            case "ollama":
                if ChatOllama is None:
                    raise ImportError("langchain-ollama not installed. Run: pip install langchain-ollama")
                return ChatOllama(
                    base_url=settings.OLLAMA_BASE_URL,
                    model=settings.OLLAMA_MODEL,
                    temperature=0.1,
                )
            case _:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

    # ─── JSON parsing ───────────────────────────────────────────

    def _safe_parse_json(self, text: str) -> dict:
        if isinstance(text, dict):
            return text
        raw = str(text).strip()
        # Strip markdown fences
        if "```" in raw:
            lines = raw.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            raw = "\n".join(lines)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except json.JSONDecodeError:
                    pass
            return {
                "analysis": raw,
                "confidence": 0.3,
                "mitre_techniques": [],
                "recommendations": ["Manual review recommended"],
                "sources": [],
            }

    # ─── Tool-call extraction ───────────────────────────────────

    def _extract_tool_calls(self, parsed: dict) -> list[dict]:
        """Extract tool_calls from the parsed LLM response."""
        calls = parsed.get("tool_calls", [])
        if not isinstance(calls, list):
            return []
        valid = []
        for call in calls:
            if isinstance(call, dict) and "tool" in call:
                valid.append({
                    "tool": str(call["tool"]),
                    "args": call.get("args", {}),
                })
        return valid

    # ─── Investigation with tool loop ───────────────────────────

    async def investigate(self, query: str, context: dict) -> dict:
        """
        Investigation with automatic OSINT tool-calling loop.

        Flow:
        1. Build prompt with enriched context
        2. Send to LLM
        3. If response contains tool_calls → execute tools → re-prompt
        4. Repeat up to MAX_TOOL_ROUNDS times
        5. Return final analysis
        """
        system_prompt = INVESTIGATION_SYSTEM_PROMPT.replace(
            "{tool_descriptions}", TOOL_DESCRIPTIONS
        )

        # Build context string — truncate large fields intelligently
        context_str = json.dumps(context, indent=2, default=str)
        if len(context_str) > 12000:
            context_str = context_str[:12000] + "\n... (truncated)"

        tools_used: list[dict] = []
        tool_results_text = ""

        for round_num in range(MAX_TOOL_ROUNDS + 1):
            human_msg = (
                f"Investigation Query: {query}\n\n"
                f"Enriched Context (agent data, alerts, telemetry):\n{context_str}\n"
            )
            if tool_results_text:
                human_msg += f"\nTool Results from previous round:\n{tool_results_text}\n"
            human_msg += "\nProvide your investigation findings as JSON."

            # Escape curly braces so ChatPromptTemplate doesn't treat
            # JSON keys like {matched_agents} as template variables.
            safe_human = human_msg.replace("{", "{{").replace("}", "}}")

            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", safe_human),
            ])

            chain = prompt | self.llm | self.str_parser

            try:
                raw_result = await chain.ainvoke({})
            except Exception as e:
                logger.error("LLM call failed", round=round_num, error=str(e))
                return {
                    "analysis": f"LLM call failed: {e}",
                    "confidence": 0.0,
                    "recommendations": ["Check Ollama is running"],
                    "mitre_techniques": [],
                    "sources": [],
                    "tools_used": tools_used,
                }

            parsed = self._safe_parse_json(raw_result)
            tool_calls = self._extract_tool_calls(parsed)

            if not tool_calls or round_num >= MAX_TOOL_ROUNDS:
                # Final answer — no more tools needed
                parsed["tools_used"] = tools_used
                logger.info(
                    "Investigation completed",
                    query=query[:80],
                    rounds=round_num + 1,
                    tools_used=len(tools_used),
                )
                return parsed

            # ── Execute requested tools ─────────────────────────
            logger.info(
                "LLM requested tools",
                round=round_num,
                tools=[c["tool"] for c in tool_calls],
            )
            round_results = []
            for call in tool_calls[:5]:  # max 5 tool calls per round
                result = await execute_tool(call["tool"], call.get("args", {}))
                entry = {
                    "tool": call["tool"],
                    "args": call.get("args", {}),
                    "result": result,
                }
                round_results.append(entry)
                tools_used.append(entry)

            tool_results_text = json.dumps(round_results, indent=2, default=str)
            if len(tool_results_text) > 6000:
                tool_results_text = tool_results_text[:6000] + "\n... (truncated)"

        # Should not reach here but just in case
        parsed["tools_used"] = tools_used
        return parsed

    # ─── Shell output analysis ──────────────────────────────────

    # Max chars to send to the LLM in a single batch
    BATCH_CHAR_LIMIT = 14000

    # Section delimiters produced by the Rust agent's full-scan command
    _SECTION_RE = re.compile(r"^=== (.+?) ===$", re.MULTILINE)

    def _split_into_batches(self, output: str) -> list[tuple[str, str]]:
        """
        Split command output into labelled batches that each fit within
        BATCH_CHAR_LIMIT.  The agent's full-scan output uses
        ``=== SECTION NAME ===`` delimiters; we split on those first.
        For generic (non-scan) output we fall back to simple
        character-based chunking.

        Returns a list of (label, text) tuples.
        """
        sections: list[tuple[str, str]] = []
        positions = [(m.start(), m.group(1)) for m in self._SECTION_RE.finditer(output)]

        if positions:
            for idx, (start, name) in enumerate(positions):
                end = positions[idx + 1][0] if idx + 1 < len(positions) else len(output)
                sections.append((name.strip(), output[start:end].strip()))
        else:
            # No section headers — treat as a single blob
            sections.append(("full output", output))

        # Now group small sections together or split oversized ones
        batches: list[tuple[str, str]] = []
        cur_label_parts: list[str] = []
        cur_text_parts: list[str] = []
        cur_len = 0

        def _flush():
            if cur_text_parts:
                batches.append((
                    " + ".join(cur_label_parts),
                    "\n\n".join(cur_text_parts),
                ))

        for label, text in sections:
            # If a single section exceeds the limit, chunk it alone
            if len(text) > self.BATCH_CHAR_LIMIT:
                _flush()
                cur_label_parts, cur_text_parts, cur_len = [], [], 0
                # Sub-chunk by character limit
                for i in range(0, len(text), self.BATCH_CHAR_LIMIT):
                    chunk = text[i:i + self.BATCH_CHAR_LIMIT]
                    part_label = f"{label} (part {i // self.BATCH_CHAR_LIMIT + 1})"
                    batches.append((part_label, chunk))
            elif cur_len + len(text) > self.BATCH_CHAR_LIMIT:
                _flush()
                cur_label_parts = [label]
                cur_text_parts = [text]
                cur_len = len(text)
            else:
                cur_label_parts.append(label)
                cur_text_parts.append(text)
                cur_len += len(text)

        _flush()
        return batches or [("output", output[:self.BATCH_CHAR_LIMIT])]

    async def _analyze_single_batch(
        self,
        command: str,
        batch_label: str,
        batch_text: str,
        context_block: str,
        batch_num: int,
        total_batches: int,
    ) -> dict:
        """Send one batch to the LLM and return parsed findings."""
        batch_header = (
            f"Batch {batch_num}/{total_batches} — Section: {batch_label}\n"
            if total_batches > 1 else ""
        )

        human_msg = (
            f"Command executed: {command}\n"
            f"{context_block}\n"
            f"{batch_header}"
            f"--- BEGIN COMMAND OUTPUT ---\n"
            f"{batch_text}\n"
            f"--- END COMMAND OUTPUT ---\n\n"
            f"Analyze this output for security issues, vulnerabilities, and anomalies. "
            f"Respond with structured JSON."
        )

        safe_human = human_msg.replace("{", "{{").replace("}", "}}")

        prompt = ChatPromptTemplate.from_messages([
            ("system", SHELL_ANALYSIS_SYSTEM_PROMPT),
            ("human", safe_human),
        ])

        chain = prompt | self.llm | self.str_parser
        raw = await chain.ainvoke({})
        return self._safe_parse_json(raw)

    @staticmethod
    def _merge_batch_results(results: list[dict]) -> dict:
        """Merge findings from multiple batch analyses into one result."""
        all_findings: list[dict] = []
        all_recs: list[str] = []
        all_techniques: set[str] = set()
        summaries: list[str] = []
        confidences: list[float] = []
        risk_priority = {"critical": 5, "high": 4, "medium": 3, "low": 2, "clean": 1, "unknown": 0}
        worst_risk = "clean"

        for r in results:
            all_findings.extend(r.get("findings", []))
            all_recs.extend(r.get("recommendations", []))
            all_techniques.update(r.get("mitre_techniques", []))
            if r.get("summary"):
                summaries.append(r["summary"])
            confidences.append(float(r.get("confidence", 0)))
            rl = r.get("risk_level", "unknown")
            if risk_priority.get(rl, 0) > risk_priority.get(worst_risk, 0):
                worst_risk = rl

        # Deduplicate recommendations while preserving order
        seen_recs: set[str] = set()
        unique_recs: list[str] = []
        for rec in all_recs:
            if rec.lower() not in seen_recs:
                seen_recs.add(rec.lower())
                unique_recs.append(rec)

        combined_summary = " ".join(summaries) if len(summaries) <= 3 else (
            f"Analysis of {len(results)} output sections. " + " ".join(summaries[:2])
            + f" (+ {len(summaries) - 2} more sections analyzed)"
        )

        return {
            "summary": combined_summary,
            "risk_level": worst_risk,
            "findings": all_findings,
            "recommendations": unique_recs,
            "mitre_techniques": sorted(all_techniques),
            "confidence": round(sum(confidences) / len(confidences), 2) if confidences else 0.0,
            "batches_analyzed": len(results),
        }

    async def analyze_shell_output(
        self,
        command: str,
        output: str,
        agent_context: dict | None = None,
    ) -> dict:
        """
        Analyze the output of a command executed on an agent.
        Large outputs are automatically split into batches (by section
        headers when available) so nothing is lost to truncation.
        Returns structured security findings.
        """
        context_block = ""
        if agent_context:
            context_block = (
                f"\nEndpoint Context:\n"
                f"  Hostname: {agent_context.get('hostname', 'unknown')}\n"
                f"  OS: {agent_context.get('os_type', '?')} {agent_context.get('os_version', '')}\n"
                f"  IP: {agent_context.get('internal_ip', 'unknown')}\n"
                f"  Architecture: {agent_context.get('architecture', '?')}\n"
            )

        batches = self._split_into_batches(output)
        logger.info(
            "Shell output analysis starting",
            command=command[:80],
            output_len=len(output),
            batches=len(batches),
        )

        # If only one batch, fast path — no merging needed
        if len(batches) == 1:
            try:
                result = await self._analyze_single_batch(
                    command, batches[0][0], batches[0][1],
                    context_block, 1, 1,
                )
                logger.info(
                    "Shell output analysis completed (single batch)",
                    command=command[:80],
                    findings=len(result.get("findings", [])),
                )
                return result
            except Exception as e:
                logger.error("Shell output analysis failed", error=str(e))
                return {
                    "summary": f"Analysis failed: {e}",
                    "risk_level": "unknown",
                    "findings": [],
                    "recommendations": ["Verify AI provider configuration and retry."],
                    "mitre_techniques": [],
                    "confidence": 0.0,
                }

        # Multiple batches — analyze each, then merge
        batch_results: list[dict] = []
        for idx, (label, text) in enumerate(batches, 1):
            try:
                r = await self._analyze_single_batch(
                    command, label, text,
                    context_block, idx, len(batches),
                )
                batch_results.append(r)
                logger.info(
                    "Batch analysis completed",
                    batch=f"{idx}/{len(batches)}",
                    label=label[:60],
                    findings=len(r.get("findings", [])),
                )
            except Exception as e:
                logger.warning("Batch analysis failed, skipping", batch=idx, error=str(e))
                batch_results.append({
                    "summary": f"Batch {idx} ({label}) analysis failed: {e}",
                    "risk_level": "unknown",
                    "findings": [],
                    "recommendations": [],
                    "mitre_techniques": [],
                    "confidence": 0.0,
                })

        merged = self._merge_batch_results(batch_results)
        logger.info(
            "Shell output analysis completed (batched)",
            command=command[:80],
            batches=len(batches),
            total_findings=len(merged.get("findings", [])),
        )
        return merged

    # ─── Alert analysis (unchanged) ─────────────────────────────

    async def analyze_alert(self, alert_data: dict) -> dict:
        prompt = ChatPromptTemplate.from_messages([
            ("system", THREAT_ANALYSIS_SYSTEM_PROMPT),
            ("human", (
                "Analyze the following security alert:\n\n"
                "Alert Title: {title}\n"
                "Alert Description: {description}\n"
                "Detection Source: {detection_source}\n"
                "Agent OS: {os_type}\n"
                "Raw Events: {raw_events}\n"
                "Process Tree: {process_tree}\n"
                "Network Context: {network_context}\n\n"
                "Provide a comprehensive threat analysis as JSON."
            )),
        ])

        chain = prompt | self.llm | self.str_parser

        try:
            raw = await chain.ainvoke({
                "title": alert_data.get("title", "Unknown"),
                "description": alert_data.get("description", "No description"),
                "detection_source": alert_data.get("detection_source", "unknown"),
                "os_type": alert_data.get("os_type", "unknown"),
                "raw_events": str(alert_data.get("raw_events", {}))[:3000],
                "process_tree": str(alert_data.get("process_tree", {}))[:1500],
                "network_context": str(alert_data.get("network_context", {}))[:1500],
            })
            result = self._safe_parse_json(raw)
            logger.info("Alert analysis completed", alert_title=alert_data.get("title"))
            return result
        except Exception as e:
            logger.error("LLM analysis failed", error=str(e))
            return {
                "analysis": f"Analysis failed: {e}",
                "severity": "unknown",
                "confidence": 0.0,
                "mitre_techniques": [],
                "recommendations": ["Manual analysis required"],
            }
