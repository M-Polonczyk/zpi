import json
import logging
from pathlib import Path

import numpy as np
from pydantic import BaseModel
import requests
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from google import genai
from google.genai import types

from app.pfsense.config import PfSenseConfig, PfSenseOutput
from app.core.config import settings

data = np.load(Path("data/file_embeddings.npz"), allow_pickle=True)
fragmenty = data["fragmenty"]
fragmenty_embed = data["wektory"]

PFSENSE_CONFIG_INSTRUCTION = """
You are a DevOps assistant. Your task is to generate a valid pfSense configuration change in JSON format based on the provided description and context.

Rules:
- Do not add any comments, descriptions, or text.
- Do not change the rest of the configuration unless it is related to the request.
- Use the provided pfSense configuration as a reference.
"""

model = SentenceTransformer("all-MiniLM-L6-v2")

config = types.GenerateContentConfig(
        system_instruction=PFSENSE_CONFIG_INSTRUCTION,
        response_schema=PfSenseOutput,
        response_mime_type="application/json",
        # thinking_config=types.ThinkingConfig(
        #     thinking_budget=0,  # Use `0` to turn off thinking
        # ),
    )

if settings.GEMINI_API_KEY:
    client = genai.Client(api_key=settings.GEMINI_API_KEY)

def znajdz_najblizszy_fragment(opis_zmiany):
    opis_embed = model.encode([opis_zmiany])
    similarity_scores = cosine_similarity(opis_embed, fragmenty_embed)[0]
    best_index = np.argmax(similarity_scores)
    return fragmenty[best_index]


def create_prompt(context, description, config: PfSenseOutput | None = None) -> str:
    return f"""
    Konfiguracja pfSense:
    {config.model_dump() if config else "Brak konfiguracji"}

    Fragment dokumentacji:
    {context}

    Opis: {description}
    """.strip()

def generate_content_from_model(prompt) -> PfSenseOutput | None:
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=[
            types.Content(
                parts=[types.Part(text=prompt)],
            ),
        ],
        config=config,
    )
    if isinstance(response.parsed, PfSenseOutput):
        logging.info("Response: %s", response.parsed)
        return response.parsed
    if isinstance(response.parsed, BaseModel):
        return PfSenseOutput(**response.parsed.model_dump())
    if isinstance(response.text, str):
        return PfSenseOutput(**json.loads(response.text))
    return None

def generate_content_from_model_api(prompt) -> PfSenseConfig | None:
    try:
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaSyDzKUxlqQfRNYO01Jtue_7G68T7nmD7Zmw",
            headers={"Content-Type": "application/json"},
            json={
            "contents": [
                {
                "parts": [
                    {
                    "text": prompt,
                    },
                ],
                },
            ],
            },
            timeout=600,
        )
    except requests.exceptions.RequestException:
        return None

    if response.status_code == 200:
        response_data = response.json().get("response", "")
        json_data = json.loads(response_data)
        return PfSenseConfig(**json_data)
    return None


def wygeneruj_zmiane_konfiguracji(opis_zmiany, config: PfSenseConfig | PfSenseOutput | None = None):
    kontekst = znajdz_najblizszy_fragment(opis_zmiany)
    if isinstance(config, PfSenseConfig):
        config = config.to_output()
    prompt = create_prompt(kontekst, opis_zmiany, config)
    return generate_content_from_model(prompt)


if __name__ == "__main__":
    opis = "Reduce the noise from firewall logs"
    zmiana = wygeneruj_zmiane_konfiguracji(opis)
    print(f"Wygenerowana zmiana: {zmiana}")  # noqa: E501
