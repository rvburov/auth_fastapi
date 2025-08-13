# main.py - FastAPI Backend
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3
import uvicorn
from typing import Optional
from contextlib import asynccontextmanager

# Настройки
SECRET_KEY = "your-secret-key-here"  # В продакшене используйте безопасный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Lifespan для инициализации
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown (если нужно)

# Инициализация
app = FastAPI(
    title="Auth API", 
    description="API для регистрации и авторизации",
    lifespan=lifespan
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Модели данных
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    username: str
    email: str

# Функции для работы с паролями
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Функции для работы с JWT токенами
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Функции для работы с пользователями
def get_user_by_username(username: str):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_email(email: str):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(user: UserCreate):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
            (user.username, user.email, hashed_password)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False
    if not verify_password(password, user[3]):  # user[3] - hashed_password
        return False
    return user

# Функция для получения текущего пользователя
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# API эндпоинты
@app.post("/api/register", response_model=dict)
async def register(user: UserCreate):
    # Проверяем, существует ли пользователь
    if get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Создаем пользователя
    user_id = create_user(user)
    if user_id is None:
        raise HTTPException(status_code=400, detail="Failed to create user")
    
    return {"message": "User created successfully", "user_id": user_id}

@app.post("/api/login")
async def login(user: UserLogin):
    authenticated_user = authenticate_user(user.username, user.password)
    if not authenticated_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": authenticated_user[1]}, expires_delta=access_token_expires
    )
    
    # Возвращаем токен и данные пользователя
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "id": authenticated_user[0],
            "username": authenticated_user[1],
            "email": authenticated_user[2]
        }
    }

@app.get("/api/profile", response_model=User)
async def get_profile(current_user = Depends(get_current_user)):
    return User(
        id=current_user[0],
        username=current_user[1],
        email=current_user[2]
    )

# Явные OPTIONS роуты для CORS
@app.options("/api/register")
@app.options("/api/login") 
@app.options("/api/profile")
async def options_handler():
    return {"message": "OK"}

@app.get("/")
async def root():
    return {"message": "Auth API is running"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)