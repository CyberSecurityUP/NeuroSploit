import json
import logging
from typing import Dict, Any, List, Optional

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

        # Format the user prompt with dynamic context
        # Use a safe way to format, ensuring all expected keys are present or handled.
        # This assumes the template uses specific placeholders like {target_info_json}, {recon_data_json} etc.
        # For a generic solution, we pass all additional_context as a single JSON.
        try:
            formatted_prompt = user_prompt_template.format(
                user_input=user_input,
                additional_context_json=json.dumps(additional_context or {}, indent=2)
                # Add more specific placeholders if needed, like target_info_json, recon_data_json etc.
                # E.g., target_info_json=json.dumps(additional_context.get('target_info', {}), indent=2)
            )
        except KeyError as e:
            logger.error(f"Missing key in prompt template for {self.agent_name}: {e}. Falling back to basic prompt.")
            formatted_prompt = f"{user_prompt_template}\n\nContext: {json.dumps(additional_context or {}, indent=2)}\n\nInput: {user_input}"
        
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

        llm_response_text = self.llm_manager.generate(prepared_user_prompt, system_prompt)
        
        # Here's where we would integrate tool usage based on llm_response_text
        # and self.tools_allowed. This will be more complex and potentially involve
        # re-prompting the LLM or using a function-calling mechanism.
        # For now, just return the LLM's direct response.
        return {"agent_name": self.agent_name, "input": user_input, "llm_response": llm_response_text}

    def get_allowed_tools(self) -> List[str]:
        """Returns the list of tools allowed for this agent role."""
        return self.tools_allowed
