from pathlib import Path
import numpy as np
import fitz
from sentence_transformers import SentenceTransformer


# 1. Wczytaj dokumentację z pliku PDF
def wczytaj_pdf(sciezka_pdf):
    doc = fitz.open(sciezka_pdf)
    tekst = ""
    for strona in doc:
        tekst += strona.get_text()
    return tekst


# Wczytaj plik PDF (podaj swoją ścieżkę)
sciezka_pdf = Path("backend/data/pfsense-documentation.pdf")
dokumentacja = wczytaj_pdf(sciezka_pdf)


# 2. Dzielenie dokumentacji
def podziel_na_fragmenty(text, max_words=200):
    words = text.split()
    return [" ".join(words[i : i + max_words]) for i in range(0, len(words), max_words)]


fragmenty = podziel_na_fragmenty(dokumentacja)

# 3. Embeddingowanie
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddingi = model.encode(fragmenty)

# 4. Zapis do pliku
np.savez("backend/data/file_embeddings.npz", fragmenty=fragmenty, wektory=embeddingi)

print("✅ Embeddingi zapisane do file_embeddings.npz")
