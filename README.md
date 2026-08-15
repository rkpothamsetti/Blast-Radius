# Blast Radius

Upload a JSON access graph, select a compromised employee, and inspect calculated reachability, risk, critical paths, minimum-cut remediation candidates, and mandatory OpenAI analysis.

## Run locally

1. Copy `.env.example` to `.env` and set `OPENAI_API_KEY` to a non-empty key. The backend loads this project-local file at startup; restart the backend after changing it.
2. In one terminal: `cd backend; python -m venv .venv; .venv\\Scripts\\activate; pip install -r requirements.txt; uvicorn app.main:app --reload --port 8000`
3. In another terminal: `cd frontend; npm install; npm run dev`
4. Open the Vite URL, upload `sample-data/payroll-access-graph.json`, select an employee, and run the simulation.

The uploaded graph is held in browser memory. No uploads are persisted and remediation is an in-memory preview only.
