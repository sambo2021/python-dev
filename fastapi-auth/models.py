from fastapi import Depends,HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext # we use it for password hasher
from database import db


#openssl rand -hex 32
#we gonna use it to encode and decode the token
from pydantic import BaseModel


SECRET_KEY = "2cfea755f57d42cc34ce427475f5891aa92361bff9af79a360d1dafd296853d9"

# lets consider this as out data base already which have users and thier hashed password
# what is the actual password -> adrian123
# how u hashed it -> print(get_password_hash("adrian123"))




class User(BaseModel):
    username: str
    hashed_password: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None


#This parameter specifies how to handle deprecated hashing algorithms. "auto" means 
#that FastAPI will automatically handle deprecated hashing schemes and update them as needed.
#"bcrypt" is chosen. Bcrypt is a popular and secure password hashing algorithm
#This parameter specifies how to handle deprecated hashing algorithms. "auto" means that 
#FastAPI will automatically handle deprecated hashing schemes and update them as needed.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


#OAuth2PasswordBearer: This is a class provided by the fastapi.security module for handling OAuth2 password bearer authentication. 
#OAuth2 is a protocol that allows secure authorization in a standardized way.
#tokenUrl="token": This parameter specifies the URL where clients can request a token. 
#In this case, it's set to "token," meaning that when clients want to authenticate using OAuth2 password flow, 
#they should send their credentials to the "/token" endpoint.
#With this code, you've created an instance of the OAuth2PasswordBearer class named oauth2_scheme, and you can use it as a dependency in 
#your FastAPI routes. When a route depends on oauth2_scheme, FastAPI will expect clients to include an OAuth2 token in the "Authorization" 
#header of their requests. The token will be validated and can be used to identify and authenticate the user.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#plain password that u gonna enter in /token url
#hashed password that gonna be retierived from db
# this return True or False
##def verify_password(plain_password, hashed_password):
##    return pwd_context.verify(plain_password, hashed_password)

# u enter password and this return the hashed one the same in db
## def get_password_hash(password):
##     return pwd_context.hash(password)

# this will return data like -> "username"="adrian","full_name"="Adrian Luman","email"="adrian.luman@xyzcorp.com","hashed_password"="$2b$12$fNiX.PSSs4XQg0YYC5PEF.t5.aDjEvhIVYHIN5UxLXO2.9LIRHnO6","disabled"=False
def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return User(**user_data)


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    # if the user u entered is not exist 
    if not user:
        return False
    # if the user u entered exists but lets compare the password text u entered with the hashed one
    if not pwd_context.verify(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    print(f"data: {to_encode}")
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    print(f"data: {to_encode}")

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    print(f"jwt: {encoded_jwt}")
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print(f"payload: {payload}")
        username = payload.get("username")
        print(f"username: {username}")
        if username is None:
            raise credential_exception

        token_data = TokenData(username=username)
        print(f"token_data: {token_data}")
    except JWTError:
        raise credential_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


