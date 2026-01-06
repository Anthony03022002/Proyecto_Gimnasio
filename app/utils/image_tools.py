import os
from PIL import Image

ALLOWED_IMG_EXTS = {"jpg", "jpeg", "png", "webp"}

def allowed_image(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMG_EXTS

def optimizar_imagen(in_path: str, out_path: str, max_side: int = 1600, quality: int = 82) -> None:
    """
    - Redimensiona manteniendo proporción para que el lado mayor sea <= max_side
    - Convierte a JPEG optimizado (ideal para fotos progreso)
    """
    with Image.open(in_path) as im:
        # Corrige orientación EXIF si existe
        try:
            exif = im.getexif()
            orientation = exif.get(274)
            if orientation == 3:
                im = im.rotate(180, expand=True)
            elif orientation == 6:
                im = im.rotate(270, expand=True)
            elif orientation == 8:
                im = im.rotate(90, expand=True)
        except Exception:
            pass

        # Si es PNG con alpha, convertir a RGB (fondo blanco)
        if im.mode in ("RGBA", "LA"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            bg.paste(im, mask=im.split()[-1])
            im = bg
        elif im.mode != "RGB":
            im = im.convert("RGB")

        # Resize
        w, h = im.size
        scale = min(max_side / max(w, h), 1.0)
        if scale < 1.0:
            im = im.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        # Guardar JPEG optimizado
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        im.save(out_path, format="JPEG", quality=quality, optimize=True, progressive=True)
