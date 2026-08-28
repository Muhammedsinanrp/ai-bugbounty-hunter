#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Universal LLM Client
Abstracts multiple AI providers: OpenAI, Anthropic, Groq, Ollama.
Allows the tool to work with any AI backend.
"""
import asyncio
import json
import aiohttp
from typing import Optional, Dict, Any, List
from core.config import Config
from core.logger import Logger


class LLMClient:
    """
    Multi-provider LLM client. Supports OpenAI, Anthropic, Groq, and Ollama.
    Allows fallback between providers.
    """

    PROVIDER_CONFIGS = {
        "openai": {
            "base_url": "https://api.openai.com/v1/chat/completions",
            "model_field": "model",
            "auth_header": "Authorization",
            "auth_prefix": "Bearer ",
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1/messages",
            "model_field": "model",
            "auth_header": "x-api-key",
            "auth_prefix": "",
        },
        "groq": {
            "base_url": "https://api.groq.com/openai/v1/chat/completions",
            "model_field": "model",
            "auth_header": "Authorization",
            "auth_prefix": "Bearer ",
        },
        "ollama": {
            "base_url": None,  # Set from config
            "model_field": "model",
            "auth_header": None,
            "auth_prefix": "",
        },
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("LLMClient")
        self.provider = config.ai_provider
        self.model = config.get("ai", "model", default="gpt-4o")
        self.api_key = config.get("ai", "api_key", default="")
        self.temperature = config.get("ai", "temperature", default=0.1)
        self.max_tokens = config.get("ai", "max_tokens", default=4096)

        # Ollama-specific
        self.ollama_url = config.get("ai", "ollama_url", default="http://localhost:11434")
        self.ollama_model = config.get("ai", "ollama_model", default="llama3")

    async def query(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a query to the configured LLM provider."""
        if self.provider == "ollama":
            return await self._query_ollama(prompt, system, temperature, max_tokens)
        elif self.provider == "anthropic":
            return await self._query_anthropic(prompt, system, temperature, max_tokens)
        else:
            return await self._query_openai_compatible(prompt, system, temperature, max_tokens)

    async def _query_openai_compatible(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Query OpenAI-compatible API (OpenAI, Groq)."""
        provider_config = self.PROVIDER_CONFIGS.get(self.provider)
        if not provider_config:
            raise ValueError(f"Unsupported provider: {self.provider}")

        base_url = provider_config["base_url"]
        headers = {"Content-Type": "application/json"}

        if provider_config.get("auth_header") and self.api_key:
            headers[provider_config["auth_header"]] = (
                f"{provider_config['auth_prefix']}{self.api_key}"
            )

        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            provider_config["model_field"]: self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    base_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=90),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        self.logger.error(f"API error {resp.status}: {error_text[:500]}")
                        raise Exception(f"API returned {resp.status}")

                    data = await resp.json()
                    return data["choices"][0]["message"]["content"]

        except asyncio.TimeoutError:
            self.logger.error("API request timed out")
            raise
        except Exception as e:
            self.logger.error(f"API query failed: {e}")
            raise

    async def _query_anthropic(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Query Anthropic Claude API."""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature if temperature is not None else self.temperature,
        }

        if system:
            payload["system"] = system

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=90),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        raise Exception(f"Anthropic API error {resp.status}: {error_text[:500]}")

                    data = await resp.json()
                    return data["content"][0]["text"]

        except Exception as e:
            self.logger.error(f"Anthropic query failed: {e}")
            raise

    async def _query_ollama(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Query local Ollama instance."""
        url = f"{self.ollama_url}/api/chat"
        messages: List[Dict[str, str]] = []

        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.ollama_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature if temperature is not None else self.temperature,
                "num_predict": max_tokens or self.max_tokens,
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=180),
                ) as resp:
                    if resp.status != 200:
                        raise Exception(f"Ollama returned {resp.status}")

                    data = await resp.json()
                    return data["message"]["content"]

        except Exception as e:
            self.logger.error(f"Ollama query failed: {e}")
            raise

    def extract_json(self, text: str) -> Optional[str]:
        """Extract JSON object or array from LLM response text."""
        if "```json" in text:
            start = text.index("```json") + 7
            end_idx = text.find("```", start)
            return text[start: end_idx if end_idx > start else len(text)].strip()
        elif "```" in text:
            start = text.index("```") + 3
            remaining = text[start:]
            end_idx = remaining.find("```")
            return remaining[: end_idx if end_idx >= 0 else len(remaining)].strip()
        else:
            # Try JSON object
            s = text.find("{")
            e = text.rfind("}") + 1
            if s >= 0 and e > s:
                return text[s:e]
            # Try JSON array
            s = text.find("[")
            e = text.rfind("]") + 1
            if s >= 0 and e > s:
                return text[s:e]
        return None
