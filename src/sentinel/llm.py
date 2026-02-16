"""LLM provider abstraction for swappable backends."""

import os
import json
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    async def generate(self, prompt: str, system: Optional[str] = None) -> tuple[str, dict]:
        """
        Generate a response from the LLM.
        
        Returns:
            Tuple of (response_text, metadata_dict)
        """
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        """Return the model name being used."""
        pass


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY required")
        self.model = model
        self._client = None
    
    @property
    def client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("Install anthropic: pip install anthropic")
        return self._client
    
    async def generate(self, prompt: str, system: Optional[str] = None) -> tuple[str, dict]:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system or "You are a security detection engineering expert.",
            messages=[{"role": "user", "content": prompt}],
        )
        
        text = response.content[0].text
        metadata = {
            "model": self.model,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "stop_reason": response.stop_reason,
        }
        return text, metadata
    
    def get_model_name(self) -> str:
        return f"anthropic/{self.model}"


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o",
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY required")
        self.model = model
        self._client = None
    
    @property
    def client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("Install openai: pip install openai")
        return self._client
    
    async def generate(self, prompt: str, system: Optional[str] = None) -> tuple[str, dict]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=4096,
        )
        
        text = response.choices[0].message.content
        metadata = {
            "model": self.model,
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "finish_reason": response.choices[0].finish_reason,
        }
        return text, metadata
    
    def get_model_name(self) -> str:
        return f"openai/{self.model}"


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""
    
    def __init__(
        self,
        model: str = "llama3.1",
        base_url: str = "http://localhost:11434",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
    
    async def generate(self, prompt: str, system: Optional[str] = None) -> tuple[str, dict]:
        import httpx
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        
        text = data.get("response", "")
        metadata = {
            "model": self.model,
            "eval_count": data.get("eval_count"),
            "eval_duration": data.get("eval_duration"),
        }
        return text, metadata
    
    def get_model_name(self) -> str:
        return f"ollama/{self.model}"


def get_provider(
    provider: str = "anthropic",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs,
) -> LLMProvider:
    """
    Factory function to get an LLM provider.
    
    Args:
        provider: Provider name (anthropic, openai, ollama)
        model: Model name override
        api_key: API key override
        **kwargs: Additional provider-specific arguments
    
    Returns:
        LLMProvider instance
    """
    providers = {
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }
    
    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}. Choose from: {list(providers.keys())}")
    
    provider_kwargs = {}
    if api_key:
        provider_kwargs["api_key"] = api_key
    if model:
        provider_kwargs["model"] = model
    provider_kwargs.update(kwargs)
    
    return providers[provider](**provider_kwargs)
