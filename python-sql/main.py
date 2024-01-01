from sqlmodel import Field, SQLModel, Session, create_engine, select, MetaData, Table
from passlib.context import CryptContext
from datetime import datetime
from sqlalchemy import UniqueConstraint
from fastapi import HTTPException
from email_validator import EmailNotValidError, validate_email
from disposable_email_domains import blocklist
import json

class User(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("email"),)
    username: str = Field( primary_key=True)
    fullname: str
    email: str
    hashed_password: str
    join: datetime = Field(default=datetime.utcnow())
    disabled: bool = Field(default=False)
    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

##https://github.com/s-azizkhan/fastapi-email-validation-server/blob/main/main.py
def validate_email_data(email: str):
    """
    Validates the given email data against general email rules and a disposable email blocklist.
    Parameters:
        email (str): The email address to be validated.
    Returns:
        dict: A dictionary containing the validated email address and a message indicating its validity.
        The dictionary has the following keys:
            - email (str): The validated email address.
            - message (str): A message indicating the validity of the email.
    Raises:
        HTTPException: If the email address is found in the disposable email blocklist.
    """
    try:
        # Validate against general email rules
        v = validate_email(email, check_deliverability=True)

        # Check if the domain is in the disposable email blocklist
        domain = email.split("@")[1]
        if domain in blocklist:
            raise HTTPException(
                status_code=400,
                detail=f"Disposable email addresses are not allowed: {email}",
            )

        return True
    except EmailNotValidError as e:
        return False
    except Exception as e:
        return False

def validate_data(user: User):
    return validate_email_data(user.email) and type(user.username) == str and type(user.fullname) == str


def get_user(username: str):
    with Session(engine) as session:
        user = session.get(User, username)
        return user

def add_user(user: User):
    exist_user = get_user(user.username)
    if not exist_user and validate_data(user):
        with Session(engine) as session:
            session.add(user,_warn=True)
            session.commit()
    else:
        raise HTTPException(status_code=409, detail=f"user {user.fullname} exists")

def get_all_users():
    with Session(engine) as session:
        statement = select(User)
        users = session.exec(statement).fetchall()
        return users


# Example usage
if __name__ == "__main__":
    #Hashing and verifying passwords
    tom = User(
        username = "tom", 
        fullname = "Tom Hessen",
        email = "tom.hessen@xyzcorp.com",
        hashed_password = hash_password("tom123"))
    
    adrian = User(
        username = "adrian", 
        fullname = "Adrian Phill",
        email = "adrian.fphill@xyzcorp.com",
        hashed_password = hash_password("adrian123"))
    
    hany = User(
        username = "hany", 
        fullname = "Hany Phill",
        email = "hany.phill@xyzcorp.com",
        hashed_password = hash_password("hany123"))
    
    # engine = create_engine("sqlite:///database.db",echo=True)
    # SQLModel.metadata.create_all(engine)





    byte_data = b'{  \r\n    "username" : "adrianphill", \r\n    "fullname" :"Adrian Phill",\r\n    "email" : "Adrian.Phill@gmail.com",\r\n    "password" : "adrianphill"\r\n}'

    # Decode the bytes to a string
    json_str = byte_data.decode('utf-8')

    # Parse the string as JSON
    json_data = json.loads(json_str)

    print(json_data)
                    
                       
                       
            
