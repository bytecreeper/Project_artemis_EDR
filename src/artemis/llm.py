"""LLM provider abstraction for swappable backends."""

import os
import json
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
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
            Generated text
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
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        response = await self.client.messages.create(
            model=model or self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system or "You are a security detection engineering expert.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
    
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
    
    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        response = await self.client.chat.completions.create(
            model=model or self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return response.choices[0].message.content
    
    def get_model_name(self) -> str:
        return f"openai/{self.model}"


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""
    
    def __init__(
        self,
        model: str = "llama3.1",
        base_url: Optional[str] = None,
        timeout: int = 600,  # 10 minutes for large reasoning models
    ):
        self.model = model
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
        self.timeout = timeout
    
    def _strip_reasoning_tags(self, text: str) -> str:
        """Strip <think>...</think> tags from reasoning model output."""
        import re
        # Remove <think>...</think> blocks (DeepSeek R1 chain-of-thought)
        cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        return cleaned.strip()
    
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
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        
        raw_text = data.get("response", "")
        # Strip reasoning tags for R1/reasoning models
        return self._strip_reasoning_tags(raw_text)
    
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
