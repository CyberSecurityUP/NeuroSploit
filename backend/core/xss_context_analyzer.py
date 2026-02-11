"""
NeuroSploit v3 - XSS Context Analyzer

Determines whether a payload reflected in HTML is in an executable position
(auto-executing, interactive, or non-executable text content).

Used by XSS testers and response verifier for context-aware validation.
"""
import re
from typing import Dict, Optional


# Auto-executing events (fire without user interaction)
AUTO_FIRE_EVENTS = {
    "onload", "onerror", "onabort", "onbegin", "onend", "onanimationend",
    "onanimationstart", "ontransitionend", "onhashchange", "onpageshow",
    "onpopstate", "onresize", "onscroll", "onstorage", "onunload",
    "ontoggle",  # when paired with <details open>
}

# Interactive events (require user action)
INTERACTIVE_EVENTS = {
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
    "onmousemove", "onmouseout", "onmouseenter", "onmouseleave",
    "onkeypress", "onkeydown", "onkeyup", "onfocus", "onblur",
    "onchange", "onsubmit", "onreset", "onselect", "oninput",
    "oncontextmenu", "oncopy", "oncut", "onpaste", "ondrag", "ondrop",
    "onpointerdown", "onpointerup", "onpointerover", "onpointermove",
    "ontouchstart", "ontouchend", "ontouchmove", "onfocusin", "onfocusout",
    "onauxclick", "onsearch",
}

ALL_EVENTS = AUTO_FIRE_EVENTS | INTERACTIVE_EVENTS

# Tags that auto-fire events
AUTO_FIRE_TAGS = {
    "script": True,  # auto-executes content
    "img": {"onerror"},
    "video": {"onerror"},
    "audio": {"onerror"},
    "source": {"onerror"},
    "object": {"onerror"},
    "embed": {"onerror"},
    "body": {"onload"},
    "svg": {"onload"},
    "math": set(),
    "input": {"onfocus"},  # with autofocus
    "select": {"onfocus"},
    "textarea": {"onfocus"},
    "details": {"ontoggle"},  # with open attribute
}

# Safe containers that suppress execution
SAFE_CONTAINERS = {"textarea", "title", "noscript", "xmp", "plaintext", "listing"}

# Pattern to find the innermost enclosing tag
_RE_BEFORE_TAG = re.compile(r'<(\w+)(?:\s[^>]*)?>(?=[^<]*$)', re.IGNORECASE)
_RE_OPEN_SCRIPT = re.compile(r'<script\b[^>]*>', re.IGNORECASE)
_RE_CLOSE_SCRIPT = re.compile(r'</script\b', re.IGNORECASE)
_RE_COMMENT_OPEN = re.compile(r'<!--(?!.*-->)', re.DOTALL)
_RE_STYLE_OPEN = re.compile(r'<style\b[^>]*>', re.IGNORECASE)
_RE_STYLE_CLOSE = re.compile(r'</style\b', re.IGNORECASE)
_RE_EVENT_ATTR = re.compile(r'(on\w+)\s*=\s*["\']?', re.IGNORECASE)
_RE_JS_URI = re.compile(r'(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:', re.IGNORECASE)


def analyze_xss_execution_context(
    html_body: str,
    payload: str,
    payload_lower: Optional[str] = None,
) -> Dict:
    """
    Determine whether a payload reflected in HTML is in an executable position.

    Returns:
        {
            "executable": bool,     # True if payload can auto-execute (no user action)
            "interactive": bool,    # True if payload executes WITH user interaction
            "context": str,         # Context identifier
            "confidence": float,    # 0.0 - 1.0
            "detail": str,          # Human-readable explanation
        }
    """
    result = {
        "executable": False,
        "interactive": False,
        "context": "not_found",
        "confidence": 0.0,
        "detail": "Payload not found in response",
    }

    if not html_body or not payload:
        return result

    if payload_lower is None:
        payload_lower = payload.lower()

    body_lower = html_body.lower()

    # Find payload position (try exact first, then case-insensitive)
    pos = html_body.find(payload)
    if pos == -1:
        pos = body_lower.find(payload_lower)
    if pos == -1:
        return result

    # Extract surrounding context
    before_start = max(0, pos - 300)
    after_end = min(len(html_body), pos + len(payload) + 150)
    before = html_body[before_start:pos]
    after = html_body[pos + len(payload):after_end]
    before_lower = before.lower()
    after_lower = after.lower()

    # Check for HTML encoding of the payload
    encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    if encoded_payload != payload and encoded_payload in html_body:
        # The payload appears HTML-encoded
        result.update({
            "context": "encoded",
            "confidence": 0.1,
            "detail": f"Payload appears HTML-encoded (&lt;/&gt;)",
        })
        return result

    # --- Check 1: Inside HTML comment ---
    if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
        result.update({
            "context": "html_comment",
            "confidence": 0.1,
            "detail": "Payload inside HTML comment",
        })
        return result

    # --- Check 2: Inside <script> tag ---
    script_opens = list(_RE_OPEN_SCRIPT.finditer(before))
    script_closes = list(_RE_CLOSE_SCRIPT.finditer(before))
    if script_opens:
        last_open = script_opens[-1].end()
        last_close = script_closes[-1].start() if script_closes else -1
        if last_open > last_close:
            # We're inside a <script> block
            # Check if payload breaks out of a JS string
            if _payload_breaks_js_string(before[last_open:], payload):
                result.update({
                    "executable": True,
                    "context": "script_breakout",
                    "confidence": 0.95,
                    "detail": "Payload breaks out of JS string inside <script> tag",
                })
                return result
            # Check if payload introduces new code (not just a data value)
            if any(kw in payload_lower for kw in ["alert(", "confirm(", "prompt(", "eval(", "function(", "document.", "window."]):
                result.update({
                    "executable": True,
                    "context": "script_body",
                    "confidence": 0.90,
                    "detail": "Payload with JS execution inside <script> tag",
                })
                return result
            result.update({
                "executable": True,
                "context": "script_body",
                "confidence": 0.85,
                "detail": "Payload inside <script> tag",
            })
            return result

    # --- Check 3: Inside <style> tag (safe) ---
    style_opens = list(_RE_STYLE_OPEN.finditer(before_lower))
    style_closes = list(_RE_STYLE_CLOSE.finditer(before_lower))
    if style_opens:
        last_open = style_opens[-1].end()
        last_close = style_closes[-1].start() if style_closes else -1
        if last_open > last_close:
            result.update({
                "context": "safe_container",
                "confidence": 0.1,
                "detail": "Payload inside <style> tag",
            })
            return result

    # --- Check 4: Inside a safe container ---
    for container in SAFE_CONTAINERS:
        open_pat = f"<{container}"
        close_pat = f"</{container}"
        if open_pat in before_lower:
            last_open = before_lower.rfind(open_pat)
            last_close = before_lower.rfind(close_pat)
            if last_open > last_close:
                result.update({
                    "context": "safe_container",
                    "confidence": 0.1,
                    "detail": f"Payload inside <{container}> (safe container)",
                })
                return result

    # --- Check 5: Payload itself introduces a new HTML tag ---
    if "<" in payload:
        return _analyze_injected_tag(payload, payload_lower, result)

    # --- Check 6: Determine if we're inside an HTML tag (attributes) or text content ---
    # Find the last `<` in `before` and check if there's a `>` after it
    last_lt = before.rfind("<")
    in_tag = False
    tag_name = ""
    tag_region_before = ""

    if last_lt >= 0:
        # Text between last < and payload position
        tag_region_before = before[last_lt:]
        # If no > after the last <, we're inside an open tag (attribute region)
        if ">" not in tag_region_before:
            in_tag = True
            # Extract tag name
            tm = re.match(r'<(\w+)', tag_region_before)
            if tm:
                tag_name = tm.group(1).lower()

    if in_tag and tag_name:
        # We're inside a tag's attribute region
        # Build the full attribute region: from <tag... to the closing >
        first_gt = after.find(">")
        after_to_close = after[:first_gt] if first_gt >= 0 else after
        full_attr = tag_region_before + payload + after_to_close
        full_attr_lower = full_attr.lower()

        # Check if payload is the VALUE of an event handler attribute
        # Look for on*= patterns in the text BEFORE the payload (within the tag)
        before_in_tag = tag_region_before.lower()
        for m in _RE_EVENT_ATTR.finditer(before_in_tag):
            event_name = m.group(1).lower()
            # This event is BEFORE the payload — payload is (part of) its value
            if event_name in AUTO_FIRE_EVENTS:
                result.update({
                    "executable": True,
                    "interactive": False,
                    "context": "event_handler_auto",
                    "confidence": 0.95,
                    "detail": f"Payload is value of auto-firing event '{event_name}' on <{tag_name}>",
                })
                return result
            elif event_name in INTERACTIVE_EVENTS:
                result.update({
                    "executable": False,
                    "interactive": True,
                    "context": "event_handler",
                    "confidence": 0.90,
                    "detail": f"Payload is value of interactive event '{event_name}' on <{tag_name}> (requires user action)",
                })
                return result

        # Check if we're inside a javascript: URI attribute
        if _RE_JS_URI.search(before_in_tag):
            result.update({
                "executable": False,
                "interactive": True,
                "context": "javascript_uri",
                "confidence": 0.90,
                "detail": f"Payload inside javascript: URI on <{tag_name}>",
            })
            return result

        # Check if payload creates an event handler via attribute breakout
        if _payload_creates_event(payload_lower):
            # Check if autofocus is also present (makes onfocus auto-fire)
            combined = (payload_lower + after_to_close.lower())
            has_autofocus = "autofocus" in combined
            for evt in ALL_EVENTS:
                pat = rf'{evt}\s*='
                if re.search(pat, payload_lower):
                    if evt == "onfocus" and has_autofocus:
                        result.update({
                            "executable": True,
                            "interactive": False,
                            "context": "attribute_breakout_auto",
                            "confidence": 0.95,
                            "detail": f"Payload breaks attribute to create {evt}+autofocus on <{tag_name}> (auto-fires)",
                        })
                        return result
                    elif evt in AUTO_FIRE_EVENTS:
                        result.update({
                            "executable": True,
                            "interactive": False,
                            "context": "attribute_breakout_auto",
                            "confidence": 0.90,
                            "detail": f"Payload breaks attribute to create auto-firing {evt} on <{tag_name}>",
                        })
                        return result
                    else:
                        result.update({
                            "executable": False,
                            "interactive": True,
                            "context": "attribute_breakout_event",
                            "confidence": 0.90,
                            "detail": f"Payload breaks attribute to create {evt} on <{tag_name}> (requires interaction)",
                        })
                        return result

        # Inside a regular attribute value (not event handler, not JS URI)
        result.update({
            "context": "attribute_value",
            "confidence": 0.3,
            "detail": f"Payload inside non-event attribute of <{tag_name}>",
        })
        return result

    # --- Check 7: Payload contains event handler patterns but is in text content ---
    # (e.g., "onclick=alert(1)" as literal text, NOT inside a tag)
    # This is NOT executable — it's just text

    # --- Check 8: Plain text content ---
    result.update({
        "context": "text_content",
        "confidence": 0.2,
        "detail": "Payload reflected as plain text content in HTML body",
    })
    return result


def _payload_breaks_js_string(js_before: str, payload: str) -> bool:
    """Check if payload breaks out of a JS string context."""
    # Look for string delimiters just before payload
    stripped = js_before.rstrip()
    if not stripped:
        return False
    # Payload starts with string terminator + code
    p = payload.lstrip()
    if p and p[0] in ("'", '"', '`'):
        return True
    # Payload contains </script>
    if "</script>" in payload.lower():
        return True
    return False


def _payload_creates_event(payload_lower: str) -> bool:
    """Check if payload string creates an event handler (attribute breakout)."""
    for evt in ALL_EVENTS:
        if evt in payload_lower and "=" in payload_lower:
            # e.g., " onfocus=alert(1) autofocus x="
            pat = rf'{evt}\s*='
            if re.search(pat, payload_lower):
                return True
    return False


def _analyze_injected_tag(payload: str, payload_lower: str, result: Dict) -> Dict:
    """Analyze a payload that introduces new HTML tags."""
    # Extract tags from payload
    tags = re.findall(r'<(\w+)', payload_lower)
    if not tags:
        result.update({
            "context": "text_content",
            "confidence": 0.3,
            "detail": "Payload contains < but no recognizable tags",
        })
        return result

    primary_tag = tags[0]

    # <script> tag = auto-execute
    if "script" in tags:
        result.update({
            "executable": True,
            "context": "injected_script_tag",
            "confidence": 0.95,
            "detail": f"Payload injects <script> tag",
        })
        return result

    # Check for event handlers in the payload
    events_in_payload = set()
    for m in _RE_EVENT_ATTR.finditer(payload_lower):
        events_in_payload.add(m.group(1).lower())

    auto_events = events_in_payload & AUTO_FIRE_EVENTS
    interactive_events = events_in_payload & INTERACTIVE_EVENTS

    # Check for autofocus (makes onfocus auto-fire)
    has_autofocus = "autofocus" in payload_lower
    if has_autofocus and "onfocus" in events_in_payload:
        auto_events.add("onfocus")
        interactive_events.discard("onfocus")

    # Check for <details open ontoggle>
    if "details" in tags and "open" in payload_lower and "ontoggle" in events_in_payload:
        auto_events.add("ontoggle")
        interactive_events.discard("ontoggle")

    # img/video/audio with src=x onerror → auto-fires
    if primary_tag in ("img", "video", "audio", "source", "object", "embed", "input"):
        if "onerror" in events_in_payload and ("src=" in payload_lower or "src =" in payload_lower):
            auto_events.add("onerror")
            interactive_events.discard("onerror")

    # svg/body onload → auto-fires
    if primary_tag in ("svg", "body", "math") and "onload" in events_in_payload:
        auto_events.add("onload")
        interactive_events.discard("onload")

    # SVG animate/set onbegin → auto-fires
    if primary_tag in ("animate", "animatetransform", "set", "discard") and "onbegin" in events_in_payload:
        auto_events.add("onbegin")
        interactive_events.discard("onbegin")

    # javascript: URI
    if "javascript:" in payload_lower:
        result.update({
            "executable": False,
            "interactive": True,
            "context": "injected_js_uri",
            "confidence": 0.90,
            "detail": f"Payload injects <{primary_tag}> with javascript: URI",
        })
        return result

    if auto_events:
        result.update({
            "executable": True,
            "interactive": False,
            "context": "injected_tag_auto",
            "confidence": 0.95,
            "detail": f"Payload injects <{primary_tag}> with auto-firing event(s): {', '.join(auto_events)}",
        })
        return result

    if interactive_events:
        result.update({
            "executable": False,
            "interactive": True,
            "context": "injected_tag_interactive",
            "confidence": 0.85,
            "detail": f"Payload injects <{primary_tag}> with interactive event(s): {', '.join(interactive_events)}",
        })
        return result

    # Tag injected but no events
    result.update({
        "context": "injected_tag_no_event",
        "confidence": 0.4,
        "detail": f"Payload injects <{primary_tag}> but without executable event handlers",
    })
    return result
