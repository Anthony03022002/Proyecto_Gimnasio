import fitz  # PyMuPDF

def optimizar_pdf(in_path: str, out_path: str) -> None:
    doc = None
    try:
        doc = fitz.open(in_path)
        doc.save(
            out_path,
            garbage=4,
            deflate=True,
            clean=True
            # ❌ linear=True  (ya no existe)
        )
    finally:
        if doc is not None:
            doc.close()
