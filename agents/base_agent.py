import json
import logging
from typing import Dict, Any, List, Optional
import re
import subprocess
import shlex

from core.llm_manager import LLMManager

logger = logging.getLogger(__name__)

class BaseAgent:
    """
    A generic agent class that orchestrates LLM interactions, tool usage,
    and adheres to specific agent roles (e.g., Red Team, Blue Team).
    """
    def __init__(self, agent_name: str, config: Dict, llm_manager: LLMManager, context_prompts: Dict):
        self.agent_name = agent_name
        self.config = config
        self.llm_manager = llm_manager
        self.context_prompts = context_prompts # This will contain user_prompt and system_prompt for this agent role
        
        self.agent_role_config = self.config.get('agent_roles', {}).get(agent_name, {})
        self.tools_allowed = self.agent_role_config.get('tools_allowed', [])
        self.description = self.agent_role_config.get('description', 'No description provided.')
        
        logger.info(f"Initialized {self.agent_name} agent. Description: {self.description}")

    def _prepare_prompt(self, user_input: str, additional_context: Dict = None) -> str:
        """
        Prepares the user prompt for the LLM, incorporating agent-specific instructions
        and dynamic context.
        """
        user_prompt_template = self.context_prompts.get("user_prompt", "")
        if not user_prompt_template:
            logger.warning(f"No user prompt template found for agent {self.agent_name}.")
            return user_input # Fallback to raw user input

        # Create a dictionary with all the possible placeholders and default values
        format_dict = {
            "user_input": user_input,
            # For bug_bounty_hunter agent
            "target_info_json": user_input,
            "recon_data_json": json.dumps(additional_context or {}, indent=2),
            # For red_team_agent
            "mission_objectives_json": user_input,
            "target_environment_json": json.dumps(additional_context or {}, indent=2),
            # For pentest agent
            "scope_json": user_input,
            "initial_info_json": json.dumps(additional_context or {}, indent=2),
            # For blue_team_agent
            "logs_alerts_json": user_input,
            "telemetry_json": json.dumps(additional_context or {}, indent=2),
            # For exploit_expert agent
            "vulnerability_details_json": user_input,
            "target_info_json": json.dumps(additional_context or {}, indent=2),
            # For cwe_expert agent
            "code_vulnerability_json": user_input,
            # For malware_analysis agent
            "malware_sample_json": user_input,
            # For replay_attack agent
            "traffic_logs_json": user_input,
            # Generic additional context
            "additional_context_json": json.dumps(additional_context or {}, indent=2)
        }

        # Override with actual additional_context values if provided
        if additional_context:
            for key, value in additional_context.items():
                if isinstance(value, (dict, list)):
                    format_dict[f"{key}_json"] = json.dumps(value, indent=2)
                else:
                    format_dict[key] = value

        # Use a safe way to format, only including keys that exist in the template
        try:
            formatted_prompt = user_prompt_template.format_map(format_dict)
        except KeyError as e:
            logger.error(f"Missing key in format_dict: {e}")
            # Fallback to user input if formatting fails
            return user_input

        return formatted_prompt

    def execute(self, user_input: str, campaign_data: Dict = None) -> Dict:
        """
        Executes the agent's task using the LLM and potentially external tools.
        `campaign_data` can be used to pass ongoing results or context between agent executions.
        """
        logger.info(f"Executing {self.agent_name} agent for input: {user_input[:50]}...")
        
        system_prompt = self.context_prompts.get("system_prompt", "")
        if not system_prompt:
            logger.warning(f"No system prompt found for agent {self.agent_name}. Using generic system prompt.")
            system_prompt = f"You are an expert {self.agent_name}. Analyze the provided information and generate a response."

        # Prepare the user prompt with current input and campaign data
        prepared_user_prompt = self._prepare_prompt(user_input, campaign_data)

        # Loop for tool usage
        for _ in range(5): # Limit to 5 iterations to prevent infinite loops
            llm_response_text = self.llm_manager.generate(prepared_user_prompt, system_prompt)
            
            tool_name, tool_args = self._parse_llm_response(llm_response_text)

            if tool_name:
                if tool_name in self.config.get('tools', {}):
                    tool_path = self.config['tools'][tool_name]
                    tool_output = self._execute_tool(tool_path, tool_args)
                    prepared_user_prompt += f"\n\n[TOOL_OUTPUT]\n{tool_output}"
                else:
                    if self._ask_for_permission(f"Tool '{tool_name}' not found. Do you want to try to download it?"):
                        self.download_tool(tool_name)
                        # We don't execute the tool in this iteration, but the LLM can try again in the next one
                        prepared_user_prompt += f"\n\n[TOOL_DOWNLOAD] Tool '{tool_name}' downloaded."
                    else:
                        prepared_user_prompt += f"\n\n[TOOL_ERROR] Tool '{tool_name}' not found and permission to download was denied."
            else:
                return {"agent_name": self.agent_name, "input": user_input, "llm_response": llm_response_text}

        return {"agent_name": self.agent_name, "input": user_input, "llm_response": llm_response_text}

    def _parse_llm_response(self, response: str) -> (Optional[str], Optional[str]):
        """
        Parses the LLM response to find a tool to use.
        Supports both single tool format and multiple tool chain format.
        """
        # Single tool format: [TOOL] toolname: args
        match = re.search(r"\[TOOL\]\s*(\w+)\s*:\s*(.*?)(?:\n|$)", response, re.MULTILINE)
        if match:
            return match.group(1), match.group(2).strip()
        return None, None

    def _parse_all_tools(self, response: str) -> List[tuple]:
        """
        Parse multiple tool calls from LLM response for tool chaining.
        Returns list of (tool_name, tool_args) tuples.
        """
        tools = []
        pattern = r"\[TOOL\]\s*(\w+)\s*:\s*(.*?)(?=\[TOOL\]|$)"
        matches = re.finditer(pattern, response, re.MULTILINE | re.DOTALL)

        for match in matches:
            tool_name = match.group(1)
            tool_args = match.group(2).strip()
            tools.append((tool_name, tool_args))

        logger.debug(f"Parsed {len(tools)} tool calls from LLM response")
        return tools

    def execute_tool_chain(self, tools: List[tuple]) -> List[Dict]:
        """
        Execute multiple tools in sequence (tool chaining).

        Args:
            tools: List of (tool_name, tool_args) tuples

        Returns:
            List[Dict]: Results from each tool execution
        """
        results = []

        for tool_name, tool_args in tools:
            logger.info(f"Executing tool in chain: {tool_name}")

            # Check if tool is allowed for this agent
            if tool_name not in self.tools_allowed and self.tools_allowed:
                logger.warning(f"Tool '{tool_name}' not allowed for agent {self.agent_name}")
                results.append({
                    "tool": tool_name,
                    "status": "denied",
                    "output": f"Tool '{tool_name}' not in allowed tools list"
                })
                continue

            # Check if tool exists in config
            if tool_name not in self.config.get('tools', {}):
                logger.warning(f"Tool '{tool_name}' not found in configuration")
                results.append({
                    "tool": tool_name,
                    "status": "not_found",
                    "output": f"Tool '{tool_name}' not configured"
                })
                continue

            # Execute the tool
            tool_path = self.config['tools'][tool_name]
            output = self._execute_tool(tool_path, tool_args)

            results.append({
                "tool": tool_name,
                "args": tool_args,
                "status": "executed",
                "output": output
            })

        return results

    def _execute_tool(self, tool_path: str, args: str) -> str:
        """
        Executes a tool safely and returns the output.
        Uses shlex for safe argument parsing and includes timeout protection.
        """
        try:
            # Sanitize and validate tool path
            if not tool_path or '..' in tool_path:
                return f"[ERROR] Invalid tool path: {tool_path}"

            # Parse arguments safely using shlex
            try:
                args_list = shlex.split(args) if args else []
            except ValueError as e:
                return f"[ERROR] Invalid arguments: {e}"

            # Build command list (no shell=True for security)
            cmd = [tool_path] + args_list

            logger.info(f"Executing tool: {' '.join(cmd)}")

            # Execute with timeout (60 seconds default)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False  # Security: never use shell=True
            )

            # Combine stdout and stderr
            output = ""
            if result.stdout:
                output += f"[STDOUT]\n{result.stdout}\n"
            if result.stderr:
                output += f"[STDERR]\n{result.stderr}\n"
            if result.returncode != 0:
                output += f"[EXIT_CODE] {result.returncode}\n"

            return output if output else "[NO_OUTPUT]"

        except subprocess.TimeoutExpired:
            logger.error(f"Tool execution timeout: {tool_path}")
            return f"[ERROR] Tool execution timeout after 60 seconds"
        except FileNotFoundError:
            logger.error(f"Tool not found: {tool_path}")
            return f"[ERROR] Tool not found at path: {tool_path}"
        except PermissionError:
            logger.error(f"Permission denied executing: {tool_path}")
            return f"[ERROR] Permission denied for tool: {tool_path}"
        except Exception as e:
            logger.error(f"Unexpected error executing tool: {e}")
            return f"[ERROR] Unexpected error: {str(e)}"

    def _ask_for_permission(self, message: str) -> bool:
        """Asks the user for permission."""
        response = input(f"{message} (y/n): ").lower()
        return response == 'y'

    def download_tool(self, tool_name: str):
        """Downloads a tool."""
        # This is a placeholder for a more sophisticated tool download mechanism.
        # For now, we'll just log the request.
        logger.info(f"User requested to download tool: {tool_name}")
        print(f"Downloading tool '{tool_name}'... (This is a placeholder, no actual download will be performed)")

    def get_allowed_tools(self) -> List[str]:
        """Returns the list of tools allowed for this agent role."""
        return self.tools_allowed
