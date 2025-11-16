import os
import uuid
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import User as UserSchema, EngineerProfile, ServiceCategory, Job as JobSchema, Message as MessageSchema, CallLog as CallLogSchema, Payment as PaymentSchema

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="MagicFix Pro API", version="0.1.0")

# CORS: allow local dev and the Modal preview domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",
    ],
    allow_origin_regex=r"https://.*modal\.(host|run)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Helpers ------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class TokenData(BaseModel):
    user_id: str
    role: str


def get_current_user(request: Request) -> TokenData:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1]
    payload = decode_token(token)
    return TokenData(user_id=payload.get("user_id"), role=payload.get("role"))


# ------------------ Auth ------------------

class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: str = "customer"
    password: str


class LoginBody(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/register")
def register(body: RegisterBody):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    existing = db["user"].find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        name=body.name,
        email=body.email.lower(),
        phone=body.phone,
        role=body.role if body.role in ("customer", "engineer", "admin") else "customer",
        password_hash=hash_password(body.password),
    )
    user_id = create_document("user", user)

    if user.role == "engineer":
        profile = EngineerProfile(user_id=user_id)
        create_document("engineerprofile", profile)

    token = create_access_token({"user_id": user_id, "role": user.role})
    return {"token": token, "user": {"id": user_id, "name": user.name, "email": user.email, "role": user.role}}


@app.post("/auth/login")
def login(body: LoginBody):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    u = db["user"].find_one({"email": body.email.lower()})
    if not u or not verify_password(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = str(u["_id"]) if "_id" in u else u.get("id")
    token = create_access_token({"user_id": user_id, "role": u.get("role", "customer")})
    return {"token": token, "user": {"id": user_id, "name": u.get("name"), "email": u.get("email"), "role": u.get("role")}}


@app.get("/me")
def me(user: TokenData = Depends(get_current_user)):
    u = db["user"].find_one({"_id": _oid(user.user_id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "role": u.get("role")}


# ------------------ Utility ------------------
from bson import ObjectId

def _oid(s: str) -> ObjectId:
    try:
        return ObjectId(s)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    for k, v in list(doc.items()):
        if isinstance(v, ObjectId):
            doc[k] = str(v)
    return doc


# ------------------ Categories ------------------
DEFAULT_CATEGORIES = [
    {"key": "electrical", "name": "Electrical Repairs", "icon": "zap"},
    {"key": "plumbing", "name": "Plumbing", "icon": "pipe"},
    {"key": "carpentry", "name": "Carpentry", "icon": "hammer"},
    {"key": "ac", "name": "AC Repairs", "icon": "wind"},
    {"key": "cleaning", "name": "Cleaning", "icon": "broom"},
    {"key": "gardening", "name": "Gardening", "icon": "leaf"},
    {"key": "moving", "name": "Moving/Hauling", "icon": "truck"},
    {"key": "sewage", "name": "Sewage Services", "icon": "droplets"},
    {"key": "construction", "name": "Small Construction", "icon": "building"},
    {"key": "appliance", "name": "Appliance Repairs", "icon": "wrench"},
    {"key": "smarthome", "name": "Smart Home Setup", "icon": "cpu"},
    {"key": "generator", "name": "Generator/Inverter", "icon": "battery"},
]

@app.get("/categories")
def get_categories():
    cats = list(db["servicecategory"].find({"active": True})) if db else []
    if not cats and db is not None:
        # seed defaults if empty
        for c in DEFAULT_CATEGORIES:
            create_document("servicecategory", ServiceCategory(**c))
        cats = list(db["servicecategory"].find({"active": True}))
    return [_serialize(c) for c in cats]


# ------------------ Jobs ------------------
class CreateJobBody(BaseModel):
    category_key: str
    description: str
    photos: List[str] = []
    location_text: Optional[str] = None


@app.post("/jobs")
def create_job(body: CreateJobBody, user: TokenData = Depends(get_current_user)):
    if user.role != "customer":
        raise HTTPException(status_code=403, detail="Only customers can create jobs")
    job = JobSchema(
        customer_id=user.user_id,
        category_key=body.category_key,
        description=body.description,
        photos=body.photos,
        location_text=body.location_text,
    )
    job_id = create_document("job", job)
    return {"id": job_id}


@app.get("/jobs/my")
def my_jobs(user: TokenData = Depends(get_current_user)):
    q = {"customer_id": user.user_id} if user.role == "customer" else {"engineer_id": user.user_id}
    jobs = list(db["job"].find(q).sort("created_at", -1))
    return [_serialize(j) for j in jobs]


class UpdateStatusBody(BaseModel):
    status: str


@app.patch("/jobs/{job_id}/status")
def update_status(job_id: str, body: UpdateStatusBody, user: TokenData = Depends(get_current_user)):
    job = db["job"].find_one({"_id": _oid(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if user.role == "customer" and body.status not in ["paid", "reviewed"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    if user.role == "engineer" and body.status not in ["accepted", "en_route", "in_progress", "completed"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db["job"].update_one({"_id": _oid(job_id)}, {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


class AssignBody(BaseModel):
    engineer_id: str


@app.post("/jobs/{job_id}/assign")
def assign_engineer(job_id: str, body: AssignBody, user: TokenData = Depends(get_current_user)):
    if user.role not in ("admin", "engineer"):
        raise HTTPException(status_code=403, detail="Not allowed")
    db["job"].update_one({"_id": _oid(job_id)}, {"$set": {"engineer_id": body.engineer_id, "status": "matched"}})
    return {"ok": True}


# ------------------ Chat (HTTP + WS) ------------------
@app.get("/jobs/{job_id}/messages")
def list_messages(job_id: str, user: TokenData = Depends(get_current_user)):
    msgs = list(db["message"].find({"job_id": job_id}).sort("created_at", 1))
    return [_serialize(m) for m in msgs]


class SendMessageBody(BaseModel):
    text: Optional[str] = None
    image_url: Optional[str] = None
    audio_url: Optional[str] = None
    receiver_id: str


@app.post("/jobs/{job_id}/messages")
def send_message(job_id: str, body: SendMessageBody, user: TokenData = Depends(get_current_user)):
    msg = MessageSchema(job_id=job_id, sender_id=user.user_id, receiver_id=body.receiver_id, text=body.text, image_url=body.image_url, audio_url=body.audio_url)
    mid = create_document("message", msg)
    return {"id": mid}


# Simple in-memory connection manager for WS (not data storage)
class ConnectionManager:
    def __init__(self):
        self.chat_rooms: Dict[str, List[WebSocket]] = {}
        self.call_rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, ws: WebSocket, room: str, kind: str):
        await ws.accept()
        rooms = self.chat_rooms if kind == "chat" else self.call_rooms
        rooms.setdefault(room, []).append(ws)

    def disconnect(self, ws: WebSocket, room: str, kind: str):
        rooms = self.chat_rooms if kind == "chat" else self.call_rooms
        if room in rooms:
            rooms[room] = [w for w in rooms[room] if w is not ws]
            if not rooms[room]:
                rooms.pop(room, None)

    async def broadcast(self, room: str, kind: str, message: dict):
        rooms = self.chat_rooms if kind == "chat" else self.call_rooms
        for ws in rooms.get(room, []):
            await ws.send_json(message)


manager = ConnectionManager()


@app.websocket("/ws/chat/{job_id}")
async def chat_ws(websocket: WebSocket, job_id: str):
    await manager.connect(websocket, job_id, "chat")
    try:
        while True:
            data = await websocket.receive_json()
            # persist message when coming from WS
            try:
                msg = MessageSchema(job_id=job_id, sender_id=data.get("sender_id"), receiver_id=data.get("receiver_id"), text=data.get("text"), image_url=data.get("image_url"), audio_url=data.get("audio_url"))
                create_document("message", msg)
            except Exception:
                pass
            await manager.broadcast(job_id, "chat", data)
    except WebSocketDisconnect:
        manager.disconnect(websocket, job_id, "chat")


# ------------------ Calls (WebRTC signaling over WS) ------------------
class StartCallBody(BaseModel):
    job_id: str
    callee_id: str


@app.post("/calls/start")
def start_call(body: StartCallBody, user: TokenData = Depends(get_current_user)):
    # Only allow call if job is accepted or in progress and participants belong to job
    job = db["job"].find_one({"_id": _oid(body.job_id)})
    if not job:
        raise HTTPException(404, "Job not found")
    participants = {job.get("customer_id"), job.get("engineer_id")}
    if user.user_id not in participants or body.callee_id not in participants:
        raise HTTPException(403, "Not allowed")
    if job.get("status") not in ("accepted", "en_route", "in_progress", "completed"):
        raise HTTPException(400, "Call allowed only for active jobs")
    room_id = str(uuid.uuid4())
    direction = "customer_to_engineer" if user.user_id == job.get("customer_id") else "engineer_to_customer"
    log = CallLogSchema(job_id=body.job_id, caller_id=user.user_id, callee_id=body.callee_id, direction=direction, room_id=room_id, started_at=datetime.now(timezone.utc), accepted=False)
    create_document("calllog", log)
    # Push notification stub would go here
    return {"room_id": room_id}


@app.post("/calls/{room_id}/end")
def end_call(room_id: str):
    db["calllog"].update_one({"room_id": room_id}, [{"$set": {"ended_at": datetime.now(timezone.utc), "duration_sec": {"$dateDiff": {"startDate": "$started_at", "endDate": "$$NOW", "unit": "second"}}}}])
    return {"ok": True}


@app.websocket("/ws/call/{room_id}")
async def call_ws(websocket: WebSocket, room_id: str):
    await manager.connect(websocket, room_id, "call")
    try:
        while True:
            data = await websocket.receive_json()
            # data expected: {type: 'offer'|'answer'|'ice', payload: {...}}
            await manager.broadcast(room_id, "call", data)
    except WebSocketDisconnect:
        manager.disconnect(websocket, room_id, "call")


# ------------------ Payments (stubs) ------------------
class InitiatePaymentBody(BaseModel):
    job_id: str
    amount: float
    currency: str = "NGN"
    provider: str = "paystack"


@app.post("/payments/initiate")
def initiate_payment(body: InitiatePaymentBody, user: TokenData = Depends(get_current_user)):
    job = db["job"].find_one({"_id": _oid(body.job_id)})
    if not job:
        raise HTTPException(404, "Job not found")
    if user.role != "customer" or job.get("customer_id") != user.user_id:
        raise HTTPException(403, "Only the customer can pay")
    # Commission 15%
    commission = round(body.amount * 0.15, 2)
    payment = PaymentSchema(job_id=body.job_id, customer_id=user.user_id, engineer_id=job.get("engineer_id"), amount=body.amount, currency=body.currency, provider=body.provider, status="init", commission=0.15)
    pid = create_document("payment", payment)
    # In a real implementation: call Paystack/Stripe here and return authorization URL/client secret
    return {"payment_id": pid, "provider": body.provider, "authorization_url": "https://pay.example/authorize/" + pid}


@app.post("/payments/webhook/paystack")
async def paystack_webhook(payload: Dict[str, Any]):
    # Verify signature in production
    ref = payload.get("data", {}).get("reference")
    status_str = payload.get("data", {}).get("status")
    status_map = {"success": "succeeded", "failed": "failed"}
    status_final = status_map.get(status_str, "failed")
    db["payment"].update_one({"provider_ref": ref}, {"$set": {"status": status_final}})
    return {"ok": True}


@app.post("/payments/webhook/stripe")
async def stripe_webhook(payload: Dict[str, Any]):
    # Verify signature in production
    pi = payload.get("data", {}).get("object", {}).get("id")
    status_str = payload.get("data", {}).get("object", {}).get("status")
    status_map = {"succeeded": "succeeded", "requires_payment_method": "failed"}
    status_final = status_map.get(status_str, "failed")
    db["payment"].update_one({"provider_ref": pi}, {"$set": {"status": status_final}})
    return {"ok": True}


# ------------------ Admin (basic) ------------------
class ApproveEngineerBody(BaseModel):
    approved: bool


@app.patch("/admin/engineers/{user_id}/approve")
def approve_engineer(user_id: str, body: ApproveEngineerBody, admin: TokenData = Depends(get_current_user)):
    if admin.role != "admin":
        raise HTTPException(403, "Admin only")
    db["engineerprofile"].update_one({"user_id": user_id}, {"$set": {"is_approved": body.approved}})
    return {"ok": True}


# ------------------ Diagnostics ------------------
@app.get("/")
def read_root():
    return {"message": "MagicFix Pro API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or ""
            collections = db.list_collection_names()
            response["collections"] = collections[:20]
            response["connection_status"] = "Connected"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
