# Zero-Trust Security Platform — Command Center UI

This package includes the existing FastAPI/PostgreSQL security backend plus a new responsive React/Vite frontend.

## UI direction
- Light blue + grey + ivory security-console palette
- Glassmorphism panels with restrained 3D motion
- Responsive sidebar/navigation
- Real-time-friendly dashboard refresh (15s)
- Login + MFA flow
- RBAC-aware screens: unauthorized API operations are surfaced without breaking the UI
- Authenticated CSV report downloads
- Asset posture cards, trust matrix, incident queue, event stream, network observatory and AI engine

## Run with Docker

From the project root:

```powershell
docker compose up --build
```

Then open:
- Frontend: http://localhost:5173
- FastAPI: http://localhost:8000
- Swagger: http://localhost:8000/docs

Demo accounts seeded by the backend:
- admin / Admin@123
- security_analyst / Analyst@123
- operator / Operator@123
- viewer / Viewer@123

## Run frontend locally

```powershell
cd frontend
npm install
npm run dev
```

If FastAPI is not on `http://localhost:8000`, create `.env` from `.env.example` and set:

```text
VITE_API_URL=http://your-fastapi-host:8000
```

## Backend integration map

| UI area | API |
|---|---|
| Login | POST /auth/login, POST /auth/login/mfa |
| Overview | GET /dashboard/summary |
| Incidents | GET/PATCH /incidents |
| Security Events | GET /events |
| Network | GET /network/stats, GET /network/traffic |
| Devices | GET/PATCH /devices |
| Servers | GET/PATCH /servers |
| Trust Matrix | GET /trust/overview |
| Users | GET/POST /users |
| Audit | GET /audit |
| Reports | GET /export/events, /export/traffic, /export/audit, /export/incidents |
| AI Engine | GET /ml/status, POST /ml/retrain |

The frontend stores the bearer token in `localStorage`, adds it to API requests, and clears the session on a 401 response.

## Important production note

The seeded passwords are demo credentials. Change/remove them before deployment. For production, serve the frontend behind HTTPS and set a restricted CORS allow-list in FastAPI instead of `*`.
