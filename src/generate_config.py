from pathlib import Path
from typing import Optional
import numpy as np
import re
import requests
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from .pfsense.config import PfSense

data = np.load(Path("data/file_embeddings.npz"), allow_pickle=True)
fragmenty = data["fragmenty"]
fragmenty_embed = data["wektory"]

model = SentenceTransformer("all-MiniLM-L6-v2")

def znajdz_najblizszy_fragment(opis_zmiany):
    opis_embed = model.encode([opis_zmiany])
    similarity_scores = cosine_similarity(opis_embed, fragmenty_embed)[0]
    best_index = np.argmax(similarity_scores)
    return fragmenty[best_index]

def przygotuj_prompt(kontekst, opis_zmiany):
    return f"""
Jesteś asystentem DevOps. Twoim zadaniem jest wygenerować zmianę w konfiguracji systemu w formacie XML.

Zasady:
- Nie dodawaj żadnych komentarzy, opisów ani tekstu.

Fragment dokumentacji:
{kontekst}

Opis: {opis_zmiany}
Odpowiedź:
""".strip()

def zapytaj_model(prompt) -> Optional[PfSense]:
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "deepseek-r1:latest",
                "prompt": prompt,
                "stream": False,
                "format": PfSense.model_json_schema(),
            },
            timeout=180
        )
    except requests.exceptions.RequestException as e:
        print("❌ Błąd połączenia z Ollama:", e)
        return None

    if response.status_code == 200:
        odpowiedz = response.json().get("response", "").strip()
        match = re.search(r"<[^>]+>.*<\/[^>]+>", odpowiedz, re.DOTALL)
        return match.group(0).strip() if match else None
    else:
        print("❌ Błąd API:", response.status_code, response.text)
        return None

def wygeneruj_zmiane_konfiguracji(opis_zmiany):
    kontekst = znajdz_najblizszy_fragment(opis_zmiany)
    prompt = przygotuj_prompt(kontekst, opis_zmiany)
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
