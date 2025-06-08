import json
from pathlib import Path
from typing import Optional
import numpy as np
import re
import requests
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from .pfsense.config import PfSense, OLLAMA_HOST

data = np.load(Path("data/file_embeddings.npz"), allow_pickle=True)
fragmenty = data["fragmenty"]
fragmenty_embed = data["wektory"]

model = SentenceTransformer("all-MiniLM-L6-v2")


def znajdz_najblizszy_fragment(opis_zmiany):
    opis_embed = model.encode([opis_zmiany])
    similarity_scores = cosine_similarity(opis_embed, fragmenty_embed)[0]
    best_index = np.argmax(similarity_scores)
    return fragmenty[best_index]


def create_prompt(context, description, config: Optional[PfSense] = None) -> str:
    return f"""
Jesteś asystentem DevOps. Twoim zadaniem jest wygenerować poprawną zmianę konfiguracji pfSense w formacie JSON.

Zasady:
- Nie dodawaj żadnych komentarzy, opisów ani tekstu.
- Nie zmieniaj reszty konfiguracji, jeżeli nie jest to związane z zapytaniem.

Konfiguracja pfSense:
{config.model_dump() if config else "Brak konfiguracji"}

Fragment dokumentacji:
{context}

Opis: {description}
Odpowiedź:
""".strip()


def zapytaj_model(prompt) -> Optional[PfSense]:
    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": "deepseek-r1:latest",
                "prompt": prompt,
                "stream": False,
                "format": PfSense.model_json_schema(),
            },
            timeout=420,
        )
    except requests.exceptions.RequestException as e:
        print("❌ Błąd połączenia z Ollama:", e)
        return None

    if response.status_code == 200:
        response_data = response.json().get("response", "")
        json_data = json.loads(response_data)
        print(f"{json_data=}")
        return PfSense(**json_data)
    else:
        print("❌ Błąd API:", response.status_code, response.text)
        return None


def wygeneruj_zmiane_konfiguracji(opis_zmiany, config: Optional[PfSense] = None) -> Optional[PfSense]:
    kontekst = znajdz_najblizszy_fragment(opis_zmiany)
    prompt = create_prompt(kontekst, opis_zmiany, config)
    print("🔍 Najbardziej pasujący fragment:\n", kontekst)
    print("📝 Prompt wysłany do modelu:\n", prompt)
    return zapytaj_model(prompt)


if __name__ == "__main__":
    opis = "Reduce the noise from firewall logs"
    zmiana = wygeneruj_zmiane_konfiguracji(opis)
    if zmiana:
        print("✅ Wygenerowana zmiana:")
        print(zmiana)
    else:
        print("❌ Nie udało się wygenerować konfiguracji.")
