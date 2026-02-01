from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import random

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock database
users_db = {}
logs_db = []

# JWT settings
SECRET_KEY = "your-secret-key"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Models
class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class ZTPContext(BaseModel):
    user_agent: str
    time_of_day: int
    device_id: str
    ip_address: str
    patch_level: str
    firewall_status: str
    device_health_score: int

# Auth endpoints
@app.post("/auth/register")
async def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[user.username] = {"email": user.email, "password": user.password}
    return {"message": "User registered successfully"}

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username not in users_db or users_db[form_data.username]["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = jwt.encode({"sub": form_data.username, "exp": datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY)
    return {"access_token": token, "token_type": "bearer"}

# ZTP endpoint
@app.post("/access/verify")
async def verify_access(context: ZTPContext, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Mock risk calculation
    user_risk = random.randint(10, 90)
    device_risk = random.randint(10, 90)
    context_risk = random.randint(10, 90)
    
    weighted_risk_score = (user_risk * 0.40) + (device_risk * 0.35) + (context_risk * 0.25)
    
    if weighted_risk_score < 50:
        decision = "ALLOW"
    elif weighted_risk_score <= 80:
        decision = "CHALLENGE"
    else:
        decision = "DENY"
    
    # Log the access attempt
    logs_db.append({
        "username": username,
        "timestamp": datetime.now().isoformat(),
        "risk_score": weighted_risk_score,
        "decision": decision,
        "ip_address": context.ip_address
    })
    
    return {
        "user_risk": user_risk,
        "device_risk": device_risk,
        "context_risk": context_risk,
        "weighted_risk_score": weighted_risk_score,
        "decision": decision
    }

# Logs endpoint
@app.get("/access/logs")
async def get_logs(token: str = Depends(oauth2_scheme)):
    return sorted(logs_db, key=lambda x: x["timestamp"], reverse=True)

# Serve dashboard
@app.get("/")
async def dashboard():
    return FileResponse('index.html')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)