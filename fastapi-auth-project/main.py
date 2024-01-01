from datetime import timedelta
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from models import Token, User, authenticate_user, create_access_token, get_current_active_user
from database import create_db_and_tables, get_user, add_user, get_all_users, hash_password, initiate_admin
import json


app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    initiate_admin()

@app.get("/",tags=["root"])
async def read_root(request: Request, current_user: User = Depends(get_current_active_user)):
    request_header = request.headers
    request_body  = await request.body()
    return {"message":"Welcome inside first FastApi api",
            "body":request_body,
            "headers": request_header,
            "owner": current_user}


# when u login u redirected to /token to generate token by username and password
# u enter the username
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # this already get_user func from database
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"username" : user.username, "email": user.email, "fullname": user.fullname }, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", tags=["my_user"])
async def read_users_me(request: Request ,current_user: User = Depends(get_current_active_user)):
    return {
            "request_headers": request.headers,
            "owner": current_user
            }


@app.get("/users/{user_name}",tags=["user_name"])
async def read_item(user_name: str , request: Request , current_user: User = Depends(get_current_active_user)):
    user = get_user(user_name)
    if user :
       return {"user_name": user.username,
               "user_fullname": user.fullname,
               "user_email": user.email,
               "query_params": request.query_params,
               "request_headers": request.headers,
               "owner": current_user
            }
    else:
        raise HTTPException(status_code=status.HTTP_404_UNAUTHORIZED,
                            detail=f"user {user_name} is not found in database", headers={"WWW-Authenticate": "Bearer"})
       
    

@app.get("/users",tags=["users"])
async def read_item(request: Request , current_user: User = Depends(get_current_active_user)):
    return {
            "users": get_all_users(),
            "request_headers": request.headers,
            "owner": current_user
            }

@app.post("/users",tags=["add_user"])
async def read_item(request: Request , current_user: User = Depends(get_current_active_user)):
    request_body  = await request.body()
    # Decode the bytes to a string
    json_str = request_body.decode('utf-8')
    # Parse the string as JSON
    json_data = json.loads(json_str)
    new_user=User(
        username = json_data["username"], 
        fullname = json_data["fullname"],
        email = json_data["email"],
        hashed_password = hash_password(json_data["password"])
    )
    add_user(new_user)
    return {
            "request_headers": request.headers,
            "owner": current_user
            }




# @app.get("/users/me/items")
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{"item_id": 1, "owner": current_user}]

