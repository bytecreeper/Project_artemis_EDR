"""LLM provider abstraction for swappable backends."""

import os
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("artemis.llm")


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    model: str = "unknown"
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: The user prompt
            system: System prompt
            model: Model override
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            The generated text
        """
        pass
    
    def get_model_name(self) -> str:
        """Get the model name being used."""
        return getattr(self, 'model', 'unknown')


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""
    
    DEFAULT_MODEL = "claude-sonnet-4-20250514"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model or self.DEFAULT_MODEL
        
        if not self.api_key:
            raise ValueError("Anthropic API key required (ANTHROPIC_API_KEY)")
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model or self.model,
                    "max_tokens": max_tokens,
                    "system": system or "",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                },
                timeout=120.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                return data["content"][0]["text"]
            else:
                raise Exception(f"Anthropic error {response.status_code}: {response.text}")


class OpenAIProvider(LLMProvider):
    """OpenAI provider."""
    
    DEFAULT_MODEL = "gpt-4o"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or self.DEFAULT_MODEL
        
        if not self.api_key:
            raise ValueError("OpenAI API key required (OPENAI_API_KEY)")
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        import httpx
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model or self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=120.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                raise Exception(f"OpenAI error {response.status_code}: {response.text}")


class OllamaProvider(LLMProvider):
    """Ollama local inference provider."""
    
    DEFAULT_MODEL = "deepseek-r1:70b"
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: Optional[str] = None,
    ):
        self.base_url = base_url
        self.model = model or self.DEFAULT_MODEL
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        import httpx
        
        payload = {
            "model": model or self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        
        if system:
            payload["system"] = system
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "")
            else:
                raise Exception(f"Ollama error {response.status_code}: {response.text}")


def get_provider(
    provider: str = "anthropic",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs,
) -> LLMProvider:
    """
    Get an LLM provider instance.
    
    Args:
        provider: Provider name (anthropic, openai, ollama)
        model: Model name override
        api_key: API key override
        **kwargs: Additional provider arguments
        
    Returns:
        LLMProvider instance
    """
    providers = {
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }
    
    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}. Options: {list(providers.keys())}")
    
    provider_class = providers[provider]
    
    if provider == "ollama":
        return provider_class(model=model, **kwargs)
    else:
        return provider_class(api_key=api_key, model=model, **kwargs)


# =============================================================================
# LLMClient - Simplified interface for pentest module
# =============================================================================

@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: str = "ollama"
    model: str = "deepseek-r1:70b"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 8192


class LLMClient:
    """
    Unified LLM client interface for pentest module.
    
    Wraps LLMProvider for simpler usage in pentest agents.
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._provider = get_provider(
            provider=config.provider,
            model=config.model,
            api_key=config.api_key,
        )
    
    async def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """Generate a response from the LLM."""
        return await self._provider.generate(
            prompt=prompt,
            system=system,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )


def get_llm_client(
    provider: str = "ollama",
    model: str = "deepseek-r1:70b",
    api_key: Optional[str] = None,
    **kwargs
) -> LLMClient:
    """Get an LLM client with the specified configuration."""
    config = LLMConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        **{k: v for k, v in kwargs.items() if k in ['base_url', 'temperature', 'max_tokens']}
    )
    return LLMClient(config)
