from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from bson import ObjectId
import jwt
import os
from dotenv import load_dotenv
from typing import List

# Load environment variables
load_dotenv()

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI")
print(MONGO_URI)
client = MongoClient(MONGO_URI)
db = client.assignment_portal

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Pydantic Models
class User(BaseModel):
    username: str
    email: str
    password: str
    role: str  # "user" or "admin"

class Assignment(BaseModel):
    userId: str
    task: str
    admin: str
    status: str = "pending"

# Utility Functions
def get_user_by_email(email: str):
    return db.users.find_one({"email": email})

def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return password_context.hash(password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.users.find_one({"_id": ObjectId(payload["user_id"])})
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# Routes
@app.get("/")
async def root():
    return {"message": "Hello World"}
# User Registration
@app.post("/register", response_description="Register a new user")
def register_user(user: User):
    existing_user = get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    user.password = get_password_hash(user.password)
    user_data = user.model_dump()
    db.users.insert_one(user_data)
    return {"message": "User registered successfully"}

# User/Admin Login
@app.post("/login", response_description="User login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token_data = {"user_id": str(user["_id"]), "role": user["role"]}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer"}

# Upload Assignment (User Endpoint)
@app.post("/upload", response_description="Upload an assignment")
def upload_assignment(assignment: Assignment, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Not authorized to upload assignments")
    assignment.userId = str(current_user["_id"])
    db.assignments.insert_one(assignment.dict())
    return {"message": "Assignment uploaded successfully"}

# Fetch All Admins (User Endpoint)
@app.get("/admins", response_description="Fetch all admins", response_model=List[User])
def fetch_admins():
    admins = list(db.users.find({"role": "admin"}))
    return admins

# View Assignments Tagged to Admin (Admin Endpoint)
@app.get("/assignments", response_description="View assignments tagged to admin")
def view_assignments(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view assignments")
    assignments = list(db.assignments.find({"admin": current_user["username"]}))
    return assignments

# Accept Assignment (Admin Endpoint)
@app.post("/assignments/{id}/accept", response_description="Accept an assignment")
def accept_assignment(id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to accept assignments")
    result = db.assignments.update_one({"_id": ObjectId(id), "admin": current_user["username"]}, {"$set": {"status": "accepted"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Assignment not found or not authorized")
    return {"message": "Assignment accepted"}

# Reject Assignment (Admin Endpoint)
@app.post("/assignments/{id}/reject", response_description="Reject an assignment")
def reject_assignment(id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to reject assignments")
    result = db.assignments.update_one({"_id": ObjectId(id), "admin": current_user["username"]}, {"$set": {"status": "rejected"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Assignment not found or not authorized")
    return {"message": "Assignment rejected"}

# Run using `uvicorn app:app --reload`