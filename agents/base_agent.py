import json
import logging
from typing import Dict, Any, List, Optional
import re
import subprocess

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

        # Create a dictionary with all the possible placeholders
        format_dict = {
            "user_input": user_input,
            "target_info_json": user_input, # for bug_bounty_hunter
            "recon_data_json": json.dumps(additional_context or {}, indent=2), # for bug_bounty_hunter
            "additional_context_json": json.dumps(additional_context or {}, indent=2),
            "mission_objectives_json": json.dumps(additional_context or {}, indent=2) # for red_team_agent
        }

        if additional_context:
            for key, value in additional_context.items():
                if isinstance(value, (dict, list)):
                    format_dict[f"{key}_json"] = json.dumps(value, indent=2)
                else:
                    format_dict[key] = value

        # Use a safe way to format, handling missing keys gracefully
        class SafeDict(dict):
            def __missing__(self, key):
                return f"{{{key}}}"  # Return the placeholder as-is for missing keys
        
        formatted_prompt = user_prompt_template.format_map(SafeDict(format_dict))
        
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
        """Parses the LLM response to find a tool to use."""
        match = re.search(r"\[TOOL\]\s*(\w+)\s*:\s*(.*)", response)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def _execute_tool(self, tool_path: str, args: str) -> str:
        """Executes a tool and returns the output."""
        try:
            result = subprocess.run(f"{tool_path} {args}", shell=True, capture_output=True, text=True)
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error executing tool: {e}"

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
