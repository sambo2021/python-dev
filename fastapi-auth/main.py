from datetime import timedelta
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from models import Token, User, authenticate_user, create_access_token, db, get_current_active_user
from database import db
app = FastAPI()


@app.get("/",tags=["root"])
async def read_root(request: Request, current_user: User = Depends(get_current_active_user)):
    request_header = request.headers
    request_body  = request.body
    return {"message":"Welcome inside first FastApi api",
            "body":request_body,
            "headers": request_header,
            "owner": current_user}





# when u login u redirected to /token to generate token by username and password
# u enter the username
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"username" : user.username, "email": user.email, "fullname": user.full_name }, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", tags=["my-user"])
async def read_users_me(request: Request ,current_user: User = Depends(get_current_active_user)):
    return {
            "request_headers": request.headers,
            "owner": current_user
            }


@app.get("/users/{user_id}",tags=["user-id"])
async def read_item(user_id: int , request: Request , current_user: User = Depends(get_current_active_user)):
    username: str 
    if user_id <= len(list(db.keys())):
       username = list(db.keys())[user_id]
       return {"user-id": user_id,
            "user": db.get(username),
            "query_params": request.query_params,
            "request_headers": request.headers,
            "owner": current_user
            }
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
       
    

@app.get("/users",tags=["users"])
async def read_item(request: Request , current_user: User = Depends(get_current_active_user)):
    return {
            "users": list(db.keys()),
            "request_headers": request.headers,
            "owner": current_user
            }






# @app.get("/users/me/items")
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{"item_id": 1, "owner": current_user}]

