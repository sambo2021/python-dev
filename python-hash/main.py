from passlib.context import CryptContext

# Password context for hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to hash a password
def hash_password(password: str):
    return pwd_context.hash(password)


# Example usage
if __name__ == "__main__":
    #Hashing and verifying passwords
    print(hash_password("adrian123"))

                       
                       
                       
            
