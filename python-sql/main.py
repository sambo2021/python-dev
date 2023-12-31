from sqlmodel import Field, SQLModel, Session, create_engine, select
from passlib.context import CryptContext
from datetime import datetime
from sqlalchemy import UniqueConstraint



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



# Example usage
if __name__ == "__main__":
    #Hashing and verifying passwords
    tom = User(
        username = "tom", 
        fullname = "Tom Hessen",
        email = "tom.hessen@xyzcorp.com",
        hashed_password = hash_password("tom123"))


    engine = create_engine("sqlite:///database.db",echo=True)

    print("-------------------------start creating table---------------------------------")
    SQLModel.metadata.create_all(engine)
    print("-------------------------End creating table---------------------------------")

    with Session(engine) as session:
        if session.exec(select(User).where(User.username == "tom")):
            print(f"username {tom.username} exists")
            exit
        else:
            print("-------------------------adding user---------------------------------")
            session.add(tom,_warn=True)
            print("----------------------------commit-----------------------------------")
            session.commit()


    # with Session(engine) as session:
    #     statement = select(Hero).where(Hero.name == "Spider-Boy")
    #     hero = session.exec(statement).first()
    #     print(hero)
    users: list
    
    with Session(engine) as session:
        statement = select(User)
        users = session.exec(statement).all()
    for user in users:
        print(user)
        print("----------")

                       
                       
                       
            
