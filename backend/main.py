import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.risk_engine import analyze_url
from backend.chatbot import generate_chatbot_response

app = FastAPI(
    title="PHISHGUARD API",
    description="End-to-End Machine Learning Phishing URL Detection & Threat Intelligence Backend",
    version="1.0.0"
)

# CORS middleware for local frontend and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static results mount for visual charts
os.makedirs("results", exist_ok=True)
app.mount("/static/results", StaticFiles(directory="results"), name="results")

class URLAnalysisRequest(BaseModel):
    url: str

class ChatRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = None

from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"detail": "ANALYSIS UNAVAILABLE: Invalid request body. Ensure JSON payload with 'url' string is provided."}
    )

@app.get("/health")
@app.get("/api/health")
def health_check():
    meta_path = "models/metadata.json"
    models_ready = os.path.exists(meta_path)
    return {
        "status": "healthy" if models_ready else "degraded",
        "models_loaded": models_ready,
        "api_version": "1.0.0"
    }

@app.get("/analyze")
@app.get("/api/analyze")
def analyze_get_notice():
    return JSONResponse(
        status_code=405,
        content={"detail": "ANALYSIS UNAVAILABLE: /analyze requires an HTTP POST request with JSON payload: {'url': 'https://example.com'}."}
    )

@app.post("/analyze")
@app.post("/api/analyze")
def analyze_url_endpoint(request: URLAnalysisRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(
            status_code=400, 
            detail="ANALYSIS UNAVAILABLE: Provided URL input cannot be empty."
        )
        
    try:
        report = analyze_url(request.url.strip())
        return report
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"SECURITY ENGINE FAILURE: Analysis could not complete. ({str(e)})"
        )

@app.get("/chat")
@app.get("/api/chat")
def chat_get_notice():
    return JSONResponse(
        status_code=405,
        content={"detail": "CHAT UNAVAILABLE: /chat requires an HTTP POST request with JSON query payload."}
    )

@app.get("/metrics")
@app.get("/api/metrics")
def get_metrics_endpoint():
    meta_path = "results/metrics.json"
    if not os.path.exists(meta_path):
        meta_path = "models/metadata.json"
        
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            data = json.load(f)
            
        data["visualizations"] = {
            "confusion_matrix": "/static/results/confusion_matrix.png",
            "roc_curve": "/static/results/roc_curve.png",
            "feature_importance": "/static/results/feature_importance.png",
            "anomaly_visual": "/static/results/anomaly_visual.png"
        }
        return data
    else:
        raise HTTPException(status_code=404, detail="METRICS UNAVAILABLE: Model training results not found.")

@app.post("/chat")
@app.post("/api/chat")
def chat_endpoint(request: ChatRequest):
    if not request.query or not request.query.strip():
        raise HTTPException(status_code=400, detail="Query input cannot be empty.")
        
    try:
        response = generate_chatbot_response(request.query, request.context)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PhishGuard AI Assistant temporarily unavailable: {str(e)}")

# Mount frontend production build assets
frontend_dist = os.path.join("frontend", "dist")
if os.path.exists(frontend_dist):
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/")
    def serve_index():
        index_path = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "PHISHGUARD API online"}

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str = ""):
        # Ignore API and static paths
        if full_path.startswith("api/") or full_path.startswith("static/") or full_path.startswith("assets/"):
            raise HTTPException(status_code=404, detail="Resource not found")
        index_path = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "PHISHGUARD API online"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
