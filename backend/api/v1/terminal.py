"""
Terminal Agent API - Interactive infrastructure pentesting via AI chat + Docker sandbox.

Provides session-based terminal interaction with AI-guided command execution,
exploitation path tracking, and VPN status monitoring.
"""

import asyncio
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.llm_manager import LLMManager
from core.sandbox_manager import get_sandbox

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory session store
# ---------------------------------------------------------------------------
terminal_sessions: Dict[str, Dict] = {}

# ---------------------------------------------------------------------------
# Pre-built templates
# ---------------------------------------------------------------------------
TEMPLATES = {
    "network_scanner": {
        "name": "Network Scanner",
        "description": "Host discovery, port scanning, and service detection",
        "system_prompt": (
            "You are an expert network reconnaissance specialist. You guide the "
            "operator through systematic host discovery, port scanning, and service "
            "fingerprinting. Always suggest nmap flags appropriate for the situation, "
            "explain output, and recommend next steps based on discovered services. "
            "Prioritize stealth when asked and suggest timing/fragmentation options."
        ),
        "initial_commands": [
            "nmap -sn {target}",
            "nmap -sV -sC -O -p- {target}",
            "nmap -sU --top-ports 50 {target}",
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Pass-the-hash, SMB/WinRM pivoting, and SSH tunneling",
        "system_prompt": (
            "You are a lateral movement specialist. You help the operator pivot "
            "through compromised networks using techniques such as pass-the-hash, "
            "SMB relay, WinRM sessions, SSH tunneling, and SOCKS proxying. Always "
            "verify credentials before attempting pivots, suggest cleanup steps, "
            "and track which hosts have been compromised."
        ),
        "initial_commands": [
            "crackmapexec smb {target} -u '' -p ''",
            "crackmapexec smb {target} --shares -u '' -p ''",
            "ssh -D 1080 -N -f user@{target}",
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "SUID binaries, kernel exploits, cron jobs, and writable paths",
        "system_prompt": (
            "You are a privilege escalation expert for Linux and Windows systems. "
            "Guide the operator through enumeration of SUID/SGID binaries, kernel "
            "version checks, misconfigured cron jobs, writable PATH directories, "
            "sudo misconfigurations, and capability abuse. Suggest automated tools "
            "like linpeas/winpeas when appropriate and explain each finding."
        ),
        "initial_commands": [
            "id && whoami && uname -a",
            "find / -perm -4000 -type f 2>/dev/null",
            "cat /etc/crontab && ls -la /etc/cron.*",
            "echo $PATH | tr ':' '\\n' | xargs -I {} ls -ld {}",
        ],
    },
    "vpn_recon": {
        "name": "VPN Reconnaissance",
        "description": "VPN connection management and internal network discovery",
        "system_prompt": (
            "You are a VPN and internal network reconnaissance specialist. You "
            "help the operator connect to target VPNs, verify tunnel status, "
            "discover internal subnets, and enumerate services behind the VPN. "
            "Always confirm connectivity before proceeding with scans and suggest "
            "appropriate scope for internal reconnaissance."
        ),
        "initial_commands": [
            "openvpn --config client.ovpn --daemon",
            "ip addr show tun0",
            "ip route | grep tun",
            "nmap -sn 10.0.0.0/24",
        ],
    },
}

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class CreateSessionRequest(BaseModel):
    template_id: Optional[str] = None
    target: Optional[str] = ""
    name: Optional[str] = ""


class MessageRequest(BaseModel):
    message: str


class ExecuteCommandRequest(BaseModel):
    command: str
    execution_method: str = "sandbox"  # "sandbox" or "direct"


class ExploitationStepRequest(BaseModel):
    description: str
    command: Optional[str] = ""
    result: Optional[str] = ""
    step_type: str = "recon"  # recon | exploit | pivot | escalate | action


class SessionSummary(BaseModel):
    session_id: str
    name: str
    target: str
    template_id: Optional[str]
    status: str
    created_at: str
    messages_count: int
    commands_count: int


class MessageResponse(BaseModel):
    role: str
    response: str
    timestamp: str
    suggested_commands: List[str]


class CommandResult(BaseModel):
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    execution_method: str
    timestamp: str


class VPNStatus(BaseModel):
    connected: bool
    ip: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_session(
    session_id: str,
    name: str,
    target: str,
    template_id: Optional[str],
) -> Dict:
    return {
        "session_id": session_id,
        "name": name,
        "target": target,
        "template_id": template_id,
        "status": "active",
        "created_at": _now_iso(),
        "messages": [],
        "command_history": [],
        "exploitation_path": [],
        "vpn_status": {"connected": False, "ip": None},
    }


def _get_session(session_id: str) -> Dict:
    session = terminal_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session


def _build_context_string(
    messages: List[Dict],
    commands: List[Dict],
    exploitation: List[Dict],
) -> str:
    parts: List[str] = []

    if messages:
        parts.append("=== Recent Conversation ===")
        for msg in messages:
            role = msg.get("role", "unknown").upper()
            parts.append(f"[{role}] {msg.get('content', '')}")

    if commands:
        parts.append("\n=== Recent Command Results ===")
        for cmd in commands:
            parts.append(
                f"$ {cmd['command']}\n"
                f"Exit code: {cmd['exit_code']}\n"
                f"Stdout: {cmd['stdout'][:500]}\n"
                f"Stderr: {cmd['stderr'][:300]}"
            )

    if exploitation:
        parts.append("\n=== Exploitation Path ===")
        for i, step in enumerate(exploitation, 1):
            parts.append(
                f"Step {i} [{step['step_type']}]: {step['description']}"
            )
            if step.get("command"):
                parts.append(f"  Command: {step['command']}")
            if step.get("result"):
                parts.append(f"  Result: {step['result'][:300]}")

    return "\n".join(parts)


def _extract_suggested_commands(text: str) -> List[str]:
    """Extract commands from backtick-fenced code blocks."""
    blocks = re.findall(r"```(?:bash|sh|shell)?\n?(.*?)```", text, re.DOTALL)
    commands: List[str] = []
    for block in blocks:
        for line in block.strip().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
    return commands


# ---------------------------------------------------------------------------
# Template endpoints
# ---------------------------------------------------------------------------

@router.get("/templates")
async def list_templates():
    """List all available session templates."""
    result = []
    for tid, tmpl in TEMPLATES.items():
        result.append({
            "id": tid,
            "name": tmpl["name"],
            "description": tmpl["description"],
            "initial_commands": tmpl["initial_commands"],
        })
    return result


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

@router.post("/session")
async def create_session(req: CreateSessionRequest):
    """Create a new terminal session, optionally from a template."""
    session_id = str(uuid.uuid4())
    target = req.target or ""
    template_id = req.template_id

    if template_id and template_id not in TEMPLATES:
        raise HTTPException(status_code=400, detail=f"Unknown template: {template_id}")

    name = req.name or (
        TEMPLATES[template_id]["name"] if template_id else f"Session {session_id[:8]}"
    )

    session = _build_session(session_id, name, target, template_id)

    # Seed initial system message from template
    if template_id:
        tmpl = TEMPLATES[template_id]
        session["messages"].append({
            "role": "system",
            "content": tmpl["system_prompt"],
            "timestamp": _now_iso(),
            "metadata": {"template": template_id},
        })
        # Provide initial suggested commands with target interpolated
        initial_cmds = [
            cmd.replace("{target}", target) for cmd in tmpl["initial_commands"]
        ]
        session["messages"].append({
            "role": "assistant",
            "content": (
                f"Session initialised with the **{tmpl['name']}** template.\n\n"
                f"Target: `{target or '(not set)'}`\n\n"
                "Suggested starting commands:\n"
                + "\n".join(f"```\n{c}\n```" for c in initial_cmds)
            ),
            "timestamp": _now_iso(),
            "suggested_commands": initial_cmds,
        })

    terminal_sessions[session_id] = session
    return session


@router.get("/sessions")
async def list_sessions():
    """Return lightweight summaries of every session."""
    summaries = []
    for sid, s in terminal_sessions.items():
        summaries.append(
            SessionSummary(
                session_id=sid,
                name=s["name"],
                target=s["target"],
                template_id=s["template_id"],
                status=s["status"],
                created_at=s["created_at"],
                messages_count=len(s["messages"]),
                commands_count=len(s["command_history"]),
            ).model_dump()
        )
    return summaries


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Return the full session including messages, commands, and exploitation path."""
    return _get_session(session_id)


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a terminal session."""
    if session_id not in terminal_sessions:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    del terminal_sessions[session_id]
    return {"status": "deleted", "session_id": session_id}


# ---------------------------------------------------------------------------
# AI message interaction
# ---------------------------------------------------------------------------

@router.post("/sessions/{session_id}/message")
async def send_message(session_id: str, req: MessageRequest):
    """Send a user prompt to the AI and receive a response with suggested commands."""
    session = _get_session(session_id)
    user_message = req.message.strip()
    if not user_message:
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    # Record user message
    session["messages"].append({
        "role": "user",
        "content": user_message,
        "timestamp": _now_iso(),
        "metadata": {},
    })

    # Determine system prompt
    template_id = session.get("template_id")
    if template_id and template_id in TEMPLATES:
        system_prompt = TEMPLATES[template_id]["system_prompt"]
    else:
        system_prompt = (
            "You are an expert infrastructure penetration tester. Help the "
            "operator plan and execute attacks against the target. Suggest "
            "concrete commands, explain their purpose, and interpret output. "
            "Always wrap commands in fenced code blocks so they can be extracted."
        )

    # Build context window
    context_messages = session["messages"][-20:]
    context_cmds = session["command_history"][-10:]
    exploitation = session["exploitation_path"]
    context = _build_context_string(context_messages, context_cmds, exploitation)

    # Call LLM
    try:
        llm = LLMManager()
        prompt = f"{context}\n\nUser: {user_message}"
        response = await llm.generate(prompt, system_prompt)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    suggested_commands = _extract_suggested_commands(response)

    # Record assistant response
    session["messages"].append({
        "role": "assistant",
        "content": response,
        "timestamp": _now_iso(),
        "suggested_commands": suggested_commands,
    })

    return MessageResponse(
        role="assistant",
        response=response,
        timestamp=session["messages"][-1]["timestamp"],
        suggested_commands=suggested_commands,
    ).model_dump()


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

@router.post("/sessions/{session_id}/execute")
async def execute_command(session_id: str, req: ExecuteCommandRequest):
    """Execute a command in the Docker sandbox (fallback: direct shell)."""
    session = _get_session(session_id)
    command = req.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    start = time.time()
    stdout = ""
    stderr = ""
    exit_code = -1
    execution_method = "direct"

    # Use requested execution method
    use_sandbox = req.execution_method == "sandbox"

    if use_sandbox:
        try:
            sandbox = await get_sandbox()
            if sandbox and sandbox.is_available:
                result = await sandbox.execute_raw(command)
                stdout = result.stdout
                stderr = result.stderr
                exit_code = result.exit_code
                execution_method = "sandbox"
        except Exception:
            pass  # Fall through to direct execution

    # Fallback or direct execution requested
    if execution_method != "sandbox":
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            raw_stdout, raw_stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
            stdout = raw_stdout.decode(errors="replace")
            stderr = raw_stderr.decode(errors="replace")
            exit_code = proc.returncode or 0
            execution_method = "direct"
        except asyncio.TimeoutError:
            stderr = "Command timed out after 120 seconds"
            exit_code = 124
        except Exception as exc:
            stderr = str(exc)
            exit_code = 1

    duration = round(time.time() - start, 3)

    cmd_record = {
        "command": command,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration": duration,
        "execution_method": execution_method,
        "timestamp": _now_iso(),
    }
    session["command_history"].append(cmd_record)

    # Mirror into messages for AI context continuity
    output_preview = stdout[:2000] if stdout else stderr[:2000]
    session["messages"].append({
        "role": "tool",
        "content": f"$ {command}\n[exit {exit_code}] ({execution_method}, {duration}s)\n{output_preview}",
        "timestamp": cmd_record["timestamp"],
        "metadata": {"exit_code": exit_code, "execution_method": execution_method},
    })

    return CommandResult(**cmd_record).model_dump()


# ---------------------------------------------------------------------------
# Exploitation path
# ---------------------------------------------------------------------------

@router.post("/sessions/{session_id}/exploitation-path")
async def add_exploitation_step(session_id: str, req: ExploitationStepRequest):
    """Add a manual step to the exploitation path timeline."""
    session = _get_session(session_id)

    valid_types = {"recon", "exploit", "pivot", "escalate", "action"}
    if req.step_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"step_type must be one of {sorted(valid_types)}",
        )

    step = {
        "description": req.description,
        "command": req.command or "",
        "result": req.result or "",
        "timestamp": _now_iso(),
        "step_type": req.step_type,
    }
    session["exploitation_path"].append(step)
    return step


@router.get("/sessions/{session_id}/exploitation-path")
async def get_exploitation_path(session_id: str):
    """Return the full exploitation path timeline."""
    session = _get_session(session_id)
    return session["exploitation_path"]


# ---------------------------------------------------------------------------
# VPN status
# ---------------------------------------------------------------------------

@router.get("/sessions/{session_id}/vpn-status")
async def get_vpn_status(session_id: str):
    """Check OpenVPN process and tun0 interface status."""
    session = _get_session(session_id)

    connected = False
    ip_addr: Optional[str] = None

    # Check for running openvpn process
    try:
        proc = await asyncio.create_subprocess_shell(
            "pgrep -a openvpn",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        raw_stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        if proc.returncode == 0 and raw_stdout.strip():
            connected = True
    except Exception:
        pass

    # Check tun0 interface for IP
    if connected:
        try:
            proc = await asyncio.create_subprocess_shell(
                "ip addr show tun0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            raw_stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0:
                match = re.search(
                    r"inet\s+(\d+\.\d+\.\d+\.\d+)", raw_stdout.decode(errors="replace")
                )
                if match:
                    ip_addr = match.group(1)
        except Exception:
            pass

    vpn = {"connected": connected, "ip": ip_addr}
    session["vpn_status"] = vpn
    return VPNStatus(**vpn).model_dump()
