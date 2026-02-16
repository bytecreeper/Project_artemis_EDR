"""Core Sentinel class - main entry point for the library."""

import asyncio
from typing import Optional

from sentinel.models import (
    ThreatDescription,
    DetectionRule,
    GenerationResult,
    RuleFormat,
)
from sentinel.llm import LLMProvider, get_provider
from sentinel.generators import SigmaGenerator, YaraGenerator, SplunkGenerator
from sentinel.generators.base import BaseGenerator


class Sentinel:
    """
    AI-powered detection engineering platform.
    
    Generate detection rules from natural language threat descriptions.
    
    Example:
        >>> sentinel = Sentinel(provider="anthropic")
        >>> result = await sentinel.generate(
        ...     "Detect PowerShell downloading files from the internet",
        ...     format=RuleFormat.SIGMA
        ... )
        >>> print(result.rule.content)
    """
    
    def __init__(
        self,
        provider: str = "anthropic",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        **provider_kwargs,
    ):
        """
        Initialize Sentinel.
        
        Args:
            provider: LLM provider (anthropic, openai, ollama)
            model: Model name override
            api_key: API key override
            **provider_kwargs: Additional provider arguments
        """
        self.llm = get_provider(
            provider=provider,
            model=model,
            api_key=api_key,
            **provider_kwargs,
        )
        
        # Initialize generators
        self._generators: dict[RuleFormat, BaseGenerator] = {
            RuleFormat.SIGMA: SigmaGenerator(self.llm),
            RuleFormat.YARA: YaraGenerator(self.llm),
            RuleFormat.SPLUNK: SplunkGenerator(self.llm),
            # TODO: Add more generators
            # RuleFormat.KQL: KqlGenerator(self.llm),
        }
    
    def get_generator(self, format: RuleFormat) -> BaseGenerator:
        """Get the generator for a specific format."""
        if format not in self._generators:
            raise ValueError(f"Unsupported format: {format}. Available: {list(self._generators.keys())}")
        return self._generators[format]
    
    async def generate(
        self,
        description: str,
        format: RuleFormat = RuleFormat.SIGMA,
        context: Optional[str] = None,
        indicators: Optional[list[str]] = None,
        severity_hint: Optional[str] = None,
    ) -> GenerationResult:
        """
        Generate a detection rule from a threat description.
        
        Args:
            description: Natural language threat description
            format: Target rule format (default: Sigma)
            context: Additional context (log source, environment)
            indicators: Known IOCs or patterns
            severity_hint: Suggested severity (low, medium, high, critical)
        
        Returns:
            GenerationResult with the generated rule or error
        """
        from sentinel.models import Severity
        
        # Parse severity hint
        severity = None
        if severity_hint:
            try:
                severity = Severity(severity_hint.lower())
            except ValueError:
                pass
        
        threat = ThreatDescription(
            description=description,
            context=context,
            indicators=indicators,
            severity_hint=severity,
            target_format=format,
        )
        
        generator = self.get_generator(format)
        return await generator.generate(threat)
    
    def generate_sync(
        self,
        description: str,
        format: RuleFormat = RuleFormat.SIGMA,
        **kwargs,
    ) -> GenerationResult:
        """Synchronous wrapper for generate()."""
        return asyncio.run(self.generate(description, format, **kwargs))
    
    async def generate_batch(
        self,
        descriptions: list[str],
        format: RuleFormat = RuleFormat.SIGMA,
        **kwargs,
    ) -> list[GenerationResult]:
        """
        Generate rules for multiple threat descriptions.
        
        Args:
            descriptions: List of threat descriptions
            format: Target rule format
            **kwargs: Additional arguments passed to generate()
        
        Returns:
            List of GenerationResults
        """
        tasks = [
            self.generate(desc, format, **kwargs)
            for desc in descriptions
        ]
        return await asyncio.gather(*tasks)
    
    @property
    def supported_formats(self) -> list[RuleFormat]:
        """List of supported output formats."""
        return list(self._generators.keys())
    
    @property
    def model_info(self) -> str:
        """Get the current model being used."""
        return self.llm.get_model_name()
