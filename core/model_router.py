#!/usr/bin/env python3
"""
Model Router - Task-type-based LLM routing.

Routes requests to different LLM profiles based on task type:
- reasoning: Complex logic and decision-making
- analysis: Data analysis and pattern recognition
- generation: Content and payload generation
- validation: Result verification and confirmation

Enabled/disabled via config. When disabled, callers fall back to their default provider.
"""

import os
import logging
from typing import Dict, Optional, Callable

logger = logging.getLogger(__name__)


class ModelRouter:
    """Routes LLM requests to different profiles based on task type."""

    def __init__(self, config: Dict, llm_manager_factory: Callable):
        """
        Args:
            config: Full application config dict (must contain 'model_routing' and 'llm' keys)
            llm_manager_factory: Callable that takes a profile name and returns an LLMManager instance
        """
        routing_config = config.get('model_routing', {})
        self.enabled = routing_config.get('enabled', False)

        # Allow env var override
        env_override = os.getenv('ENABLE_MODEL_ROUTING', '').strip().lower()
        if env_override == 'true':
            self.enabled = True
        elif env_override == 'false':
            self.enabled = False

        self.routes = routing_config.get('routes', {})
        self.llm_manager_factory = llm_manager_factory
        self._managers = {}  # Cache LLMManager instances per profile

        if self.enabled:
            logger.info(f"Model routing enabled with routes: {list(self.routes.keys())}")
        else:
            logger.debug("Model routing disabled")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 task_type: str = "default") -> Optional[str]:
        """Route a generation request to the appropriate LLM profile.

        Returns None if routing is disabled or no route matches,
        allowing callers to fall back to their default provider.
        """
        if not self.enabled:
            return None

        profile = self.routes.get(task_type, self.routes.get('default'))
        if not profile:
            logger.debug(f"No route for task_type '{task_type}', falling back to default")
            return None

        try:
            if profile not in self._managers:
                self._managers[profile] = self.llm_manager_factory(profile)

            manager = self._managers[profile]
            logger.debug(f"Routing task_type '{task_type}' to profile '{profile}' "
                         f"(provider: {manager.provider}, model: {manager.model})")
            return manager.generate(prompt, system_prompt)

        except Exception as e:
            logger.error(f"Model routing error for profile '{profile}': {e}")
            return None

    def get_profile_for_task(self, task_type: str) -> Optional[str]:
        """Get the profile name that would handle a given task type."""
        if not self.enabled:
            return None
        return self.routes.get(task_type, self.routes.get('default'))
