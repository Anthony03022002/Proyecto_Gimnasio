import os
import shutil
import subprocess

def ffmpeg_path() -> str:
    p = os.environ.get("FFMPEG_PATH", "").strip()
    if p:
        return p
    return shutil.which("ffmpeg") or ""

def ffmpeg_disponible() -> bool:
    return bool(ffmpeg_path())

def optimizar_video_ffmpeg(in_path: str, out_path: str) -> None:
    ff = ffmpeg_path()
    if not ff:
        raise FileNotFoundError("FFmpeg no está disponible")

    cmd = [
        ff, "-y",
        "-i", in_path,
        "-vf", "scale='min(1280,iw)':-2",
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-crf", "28",
        "-c:a", "aac",
        "-b:a", "96k",
        "-movflags", "+faststart",
        out_path,
    ]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode("utf-8", errors="ignore"))
