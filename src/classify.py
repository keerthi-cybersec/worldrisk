"""
classify.py

Sends each raw feed item to Claude and returns a fully enriched WorldRisk record:

  - track            "ai_security" | "traditional_appsec"
  - item_type         "vulnerability" | "attack" | "trend" | "solution" | "breach_loss" | "owasp_update"
  - description       3-5 sentence plain-English account of what happened
  - attack_source      who/what carried it out (threat actor, malware family, research
                        team) or "N/A" if the item isn't attack-specific
  - cve_id            e.g. "CVE-2026-31337", or null if none applies
  - cvss_score        0.0-10.0 float, or null if not applicable/known
  - consequences      what the impact was or could be (data exposed, systems affected)
  - remediation       how it was/can be fixed or mitigated
  - losses            financial/data/downtime cost if reported, or null if unknown
  - tags              2-5 short keyword tags

Requires ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import json
import os
import time

import anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a threat-intelligence analyst for WorldRisk, a two-track security dashboard.

TRACK ASSIGNMENT:
- "ai_security": LLM, GenAI, AI agent security, prompt injection, model attacks
- "traditional_appsec": CVEs, web/network/app vulnerabilities, breaches, malware, OWASP classic

ITEM TYPE — pick the BEST fit using these strict rules:

"vulnerability": ANY item mentioning a CVE, a security flaw, a bug, a weakness, \
or a disclosed vulnerability in software/hardware. If CVE ID exists → always vulnerability.

"attack": Confirmed active exploitation, malware campaign, ransomware, phishing \
campaign, nation-state attack, threat actor activity, active intrusion.

"breach_loss": Data breach, data leak, records exposed, financial loss from cyber \
incident, company disclosure of compromise, reported dollar losses from attack.

"solution": Patch released, fix deployed, security update, mitigation guidance, \
new security tool, vendor advisory with remediation, defensive technique published.

"owasp_update": Any item from OWASP directly, any item mentioning OWASP Top 10, \
OWASP GenAI Top 10, OWASP LLM Top 10, or official OWASP category updates.

"trend": ONLY use this when none of the above apply. Research papers without \
a specific CVE, industry statistics, general news, opinion pieces, new \
AI model releases without security implications, conference announcements.

CRITICAL RULES:
- If an article mentions a CVE ID → item_type MUST be "vulnerability"
- If an article reports active exploitation → item_type MUST be "attack"  
- If an article reports a data breach or financial loss → item_type MUST be "breach_loss"
- If an article announces a patch or fix → item_type MUST be "solution"
- If an article mentions OWASP directly → item_type MUST be "owasp_update"
- "trend" is the LAST resort, not the default
- Microsoft Patch Tuesday articles → "solution" (patches) or "vulnerability" (CVEs)
- N-able, Fortinet, Cisco advisories → "vulnerability" or "solution"
- Ransomware reports → "attack"
- Data exposure reports → "breach_loss"

Respond with ONLY a JSON object, no preamble, no markdown fences:
{"track": "...", "item_type": "...", "description": "...", "attack_source": "...", \
"cve_id": "..." or null, "cvss_score": 0.0 or null, "consequences": "...", \
"remediation": "...", "losses": "..." or null, "tags": ["...", "..."]}
"""


def classify_item(client: anthropic.Anthropic, item: dict) -> dict:
    user_content = (
        f"Title: {item['title']}\n"
        f"Source: {item['source']}\n"
        f"Raw summary/abstract: {item.get('raw_summary', '')[:2000]}\n"
        f"Default track guess: {item.get('default_track', 'unknown')}\n"
        f"Known CVE ID (if any): {item.get('cve_id', 'none')}\n"
        f"Known CVSS score (if any): {item.get('cvss_score', 'none')}"
    )

    for attempt in range(3):
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=600,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_content}],
            )
            text = resp.content[0].text.strip()
            text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            parsed = json.loads(text)
            return {
                "track": parsed.get("track", item.get("default_track", "traditional_appsec")),
                "item_type": parsed.get("item_type", "trend"),
                "description": parsed.get("description", ""),
                "attack_source": parsed.get("attack_source", "N/A"),
                "cve_id": parsed.get("cve_id") or item.get("cve_id"),
                "cvss_score": parsed.get("cvss_score") if parsed.get("cvss_score") is not None else item.get("cvss_score"),
                "consequences": parsed.get("consequences", ""),
                "remediation": parsed.get("remediation", ""),
                "losses": parsed.get("losses"),
                "tags": parsed.get("tags", []),
            }
        except Exception as exc:
            print(f"[warn] classify attempt {attempt + 1} failed for '{item['title'][:60]}': {exc}")
            time.sleep(2 ** attempt)

    # fallback if the model call kept failing -- still usable, just thinner
    return {
        "track": item.get("default_track", "traditional_appsec"),
        "item_type": "trend",
        "description": item.get("raw_summary", "")[:400] or item["title"],
        "attack_source": "N/A",
        "cve_id": item.get("cve_id"),
        "cvss_score": item.get("cvss_score"),
        "consequences": "",
        "remediation": "",
        "losses": None,
        "tags": [],
    }


def classify_all(items: list[dict]) -> list[dict]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set in the environment.")

    client = anthropic.Anthropic(api_key=api_key)
    enriched = []
    for item in items:
        classification = classify_item(client, item)
        enriched.append({**item, **classification})
    return enriched


if __name__ == "__main__":
    sample = [{
        "id": "demo0001",
        "title": "New prompt injection technique bypasses RAG guardrails",
        "source": "Demo",
        "link": "https://example.com",
        "published": "",
        "raw_summary": "Researchers demonstrate an indirect prompt injection that "
                        "smuggles instructions inside retrieved documents, causing "
                        "an assistant to exfiltrate the user's calendar data to an "
                        "external URL.",
        "default_track": "ai_security",
    }]
    print(json.dumps(classify_all(sample), indent=2))
