#======================================================================================
# GIT TOWN API
#
# Exec in CMD: uvicorn main:app --reload
#======================================================================================

from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from google.cloud import datastore
from jose import JWTError, jwt
import json
from passlib.context import CryptContext
from passlib.utils.compat import itervalues
from pydantic import BaseModel
from typing import Optional
import os


# GLOBAL CONFIG
#======================================================================================
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "your-secret-key-goes-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "key.json"


# APP & SECURITY INITIALIZERS
#======================================================================================
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ACCESS TOKEN 
#======================================================================================
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_name: Optional[str] = None


# USER
#======================================================================================
class User(BaseModel):
    user_name: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str



# USER FUNCTIONS
#======================================================================================
def get_user(user_name: str):
    client = datastore.Client()
    entities = client.query(kind='user-api').add_filter('user_name', '=', user_name).fetch()  
    for entity in entities:
        #user_dict = {entity['user_name']: {entity['user_name'], entity['full_name'], entity['email'], entity['hashed_password'], entity['disabled']}} 
        return UserInDB(**entity)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(user_name: str, password: str):
    user = get_user(user_name)
    if not user:
        print('User not found.')
        return False
    if not verify_password(password, user.hashed_password):
        print('Password does not match.')
        return False
    return user



# USER FUNCTIONS - ASYNC
#======================================================================================
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_name: str = payload.get("sub")
        if user_name is None:
            raise credentials_exception
        token_data = TokenData(user_name=user_name)
    except JWTError:
        raise credentials_exception

    user = get_user(user_name = token_data.user_name)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user







#======================================================================================
# APP ROUTES
#======================================================================================

@app.get("/")
#async def read_root(current_user: User = Depends(get_current_active_user)): 
async def read_root(): 
    return {'Gif': 'Town'}

@app.post("/token", response_model = Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect user_name or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {"sub": user.user_name}, expires_delta = access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

"""
@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.user_name}]
""" 
   
