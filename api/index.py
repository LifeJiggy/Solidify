import sys, os, json

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root)

from server import app
from fastapi.staticfiles import StaticFiles

# Debug: check where files exist
dirs_found = []
for name in ["frontend/dist", "dist", "public"]:
    p = os.path.join(root, name)
    dirs_found.append(f"{name}:{os.path.isdir(p)}")

# Add a debug endpoint
@app.get("/api/__debug")
async def debug():
    return {"root": root, "cwd": os.getcwd(), "dirs": dirs_found}

# Mount static files
for candidate in [
    os.path.join(root, "frontend", "dist"),
    os.path.join(os.getcwd(), "frontend", "dist"),
    os.path.join(root, "dist"),
    os.path.join(os.getcwd(), "dist"),
]:
    if os.path.isdir(candidate):
        app.mount("/", StaticFiles(directory=candidate, html=True), name="static")
        break
