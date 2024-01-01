from sqlmodel import Field, SQLModel, Session, create_engine,select
from passlib.context import CryptContext
from datetime import datetime
from sqlalchemy import UniqueConstraint
from fastapi import HTTPException
from email_validator import EmailNotValidError, validate_email
from disposable_email_domains import blocklist

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, echo=True, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


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
        raise HTTPException(status_code=409, detail=f"user {exist_user.fullname} exists")


def get_all_users():
    with Session(engine) as session:
        statement = select(User)
        users = session.exec(statement).fetchall()
        return users
    
tom = User(
        username = "tom", 
        fullname = "Tom Hessen",
        email = "tom.hessen@xyzcorp.com",
        hashed_password = hash_password("tom123"))

adrian = User(
        username = "adrian", 
        fullname = "Adrian Phill",
        email = "adrian.phill@xyzcorp.com",
        hashed_password = hash_password("adrian123"))

ben = User(
        username = "ben", 
        fullname = "ben haword",
        email = "ben.haword@xyzcorp.com",
        hashed_password = hash_password("ben123"))