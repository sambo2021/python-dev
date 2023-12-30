from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

db = {
    "adrian": {
        "username": "adrian",
        "full_name": "Adrian Luman",
        "email": "adrian.lumancom",
        "hashed_password": "$2b$12$fNiX.PSSs4XQg0YYC5PEF.t5.aDjEvhIVYHIN5UxLXO2.9LIRHnO6",
        "disabled": False
    },
    "tom": {
        "username": "tom",
        "full_name": "Tom Hessen",
        "email": "tom.hessen@xyzcorp.com",
        "hashed_password": "$2b$12$tXU7PhEH/4OUHMe2Z8pqKOyVcixk9fY8F3VZkGGuZCfug.ARGK9na",
        "disabled": False
    }
}


class User(BaseModel):
    username: str
    email: EmailStr | None = Field(default=None)
    hashed_password: str
    full_name: str or None = None
    disabled: bool or None = None


    

# Password context for hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to hash a password
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to verify a password
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return User(**user_data)



# Example usage
if __name__ == "__main__":
    #Hashing and verifying passwords
    plain_password = "tom123"
    hashed_password = hash_password(plain_password)    
    print(f"Plain Password: {plain_password}")
    print(f"Hashed Password: {hashed_password}")
    print(f"Password Match: {verify_password(plain_password, hashed_password)}")

    print(f"username: {get_user(db,'adrian').username}")
    print(f"fullname: {get_user(db,'adrian').full_name}")
    print(f"email: {get_user(db,'adrian').email}")
    print(f"disabled: {get_user(db,'adrian').disabled}")
    users = list(db.keys())
    print(f"users: {users}")

                       
                       
                       
            
