import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.risk_engine import analyze_url
from backend.chatbot import generate_chatbot_response

app = FastAPI(
    title="PHISHGUARD API",
    description="End-to-End Machine Learning Phishing URL Detection & Threat Intelligence Backend",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount generated static visual results
os.makedirs("results", exist_ok=True)
app.mount("/static/results", StaticFiles(directory="results"), name="results")

class URLAnalysisRequest(BaseModel):
    url: str

class ChatRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = None

@app.get("/health")
def health_check():
    meta_path = "models/metadata.json"
    models_ready = os.path.exists(meta_path)
    return {
        "status": "healthy" if models_ready else "degraded",
        "models_loaded": models_ready,
        "api_version": "1.0.0"
    }

@app.post("/analyze")
def analyze_url_endpoint(request: URLAnalysisRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    try:
        report = analyze_url(request.url.strip())
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/metrics")
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
        raise HTTPException(status_code=404, detail="Metrics not found. Train model first.")

@app.post("/chat")
def chat_endpoint(request: ChatRequest):
    if not request.query or not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
        
    try:
        response = generate_chatbot_response(request.query, request.context)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")

# Serve frontend build if dist folder exists
frontend_dist = os.path.join("frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/")
    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str = ""):
        if full_path.startswith("api/") or full_path.startswith("static/"):
            raise HTTPException(status_code=404, detail="API endpoint not found")
        index_path = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "PHISHGUARD API online"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
