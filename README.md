# CyberSentinel AI

Network traffic classification system using a Random Forest model trained on the CIC-IDS2017 dataset.

## Project Structure

```
DWDM PROJECT/
├── backend/                 ← FastAPI backend (Python)
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── cybersentinel_model.pkl   ← not in git (add manually)
│   ├── label_encoder.pkl         ← not in git (add manually)
│   └── feature_columns.pkl       ← not in git (add manually)
│
├── cybersentinel-ai/        ← React + Vite frontend
│   ├── src/
│   ├── .env.example
│   └── vite.config.js
│
├── render.yaml              ← Render deployment blueprint
└── .gitignore
```

## Local Development

### 1 — Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Health check: http://127.0.0.1:8000/health

### 2 — Frontend

```bash
cd cybersentinel-ai
cp .env.example .env              # already set to localhost:8000
npm install
npm run dev
```

App: http://localhost:5173

## Deployment (Render)

See [`render.yaml`](./render.yaml).

1. Push this repository to GitHub.
2. In Render dashboard → **New → Blueprint** → connect your repo.
3. After both services are deployed:
   - Copy the **backend URL** → paste it as `VITE_API_URL` in the frontend service env vars, then redeploy frontend.
   - Copy the **frontend URL** → paste it as `ALLOWED_ORIGINS` in the backend service env vars, then redeploy backend.

## Model Files

The three `.pkl` files are **not tracked in git** (they are in `.gitignore`).

| File | Description |
|------|-------------|
| `cybersentinel_model.pkl` | Trained RandomForestClassifier |
| `label_encoder.pkl` | Fitted LabelEncoder |
| `feature_columns.pkl` | List of 78 training feature names |

To deploy on Render, upload the `.pkl` files using **Render Disks** or commit them directly if their size allows (scikit-learn models are typically < 100 MB).



1. CyberSentinel AI: https://cybersentinel-frontend-hm4w.onrender.com
2. Testing Website (NovaTech): https://novatech-backend-hih9.onrender.com

