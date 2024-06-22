from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, MetaData, Table, select
from sqlalchemy.exc import SQLAlchemyError
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta


# Configuration
SECRET_KEY = "d38b291ccebc18af95d4df97a0a98f9bb9eea3c820e771096fa1c5e3a58f3d53"
ALGORITHM = "HS256"

app = FastAPI()


@app.get("/")
def root():
    return {"Message": "Welcome In Our Application"}


# Cloud Database
DATABASE_URL = (r"mssql+pyodbc://db_aaa253_backenddb_admin:backend1234@SQL8006.site4now.net/db_aaa253_backenddb?driver=ODBC+Driver+17+for+SQL+Server")

engine = create_engine(DATABASE_URL)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, index=True),
    Column("user_name", String(length=255), unique=True, index=True),
    Column("user_email", String, unique=True, index=True),
    Column("user_password", String),
    Column("user_phone", String)
)

metadata.create_all(bind=engine)


# Models
class UserRegistration(BaseModel):
    user_name: str
    user_password: str
    user_email: EmailStr
    user_phone: str


class UserLogin(BaseModel):
    user_email: str
    user_password: str


class UserUpdate(BaseModel):
    user_name: str
    user_phone: str


class UserChangePassword(BaseModel):
    current_password: str
    new_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


# Password hashing
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return password_context.hash(password)


def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)


# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token_user(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            return None
        return user_email
    except jwt.JWTError:
        return None


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_email
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Database operations
def get_user(db, user_email: str):
    conn = db.connect()
    query = select(users).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()
    conn.close()
    return result


def register_user(user: UserRegistration):
    conn = engine.connect()
    hashed_password = hash_password(user.user_password)
    conn.execute(users.insert().values(
        user_name=user.user_name,
        user_password=hashed_password,
        user_email=user.user_email,
        user_phone=user.user_phone
    ))
    conn.commit()
    conn.close()


def verify_user_credentials(user_email: str, user_password: str):
    conn = engine.connect()
    query = select(users.c.user_email, users.c.user_password).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(user_password, result[1]):
        return True
    return False


def delete_user(user_email: str):
    conn = engine.connect()
    conn.execute(users.delete().where(users.c.user_email == user_email))
    conn.commit()
    conn.close()


def update_user(user_email: str, updated_user: UserUpdate):
    conn = engine.connect()
    conn.execute(users.update().where(users.c.user_email == user_email).values(
        user_name=updated_user.user_name,
        user_phone=updated_user.user_phone
    ))
    conn.commit()
    conn.close()


def change_password_user(user_email: str, current_password: str, new_password: str):
    conn = engine.connect()
    query = select(users.c.user_password).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()

    if result:
        current_hashed_password = result[0]
        if password_context.verify(current_password, current_hashed_password):
            hashed_new_password = hash_password(new_password)
            conn.execute(users.update().where(users.c.user_email == user_email).values(
                user_password=hashed_new_password
            ))
            conn.commit()
            conn.close()
            return {"message": "Password changed successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


# Routes
@app.post("/register_user", response_model=Token)
async def register_user_route(user: UserRegistration):
    existing_user = get_user(engine, user.user_email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already Registered")

    register_user(user)
    access_token = create_access_token_user(
        data={"sub": user.user_email}
    )
    return {"Message": "This Account Registered Successful", "access_token": access_token, "token_type": "bearer"}


@app.post("/login_user")
async def login_user_route(users: UserLogin):
    user_email = users.user_email
    user_password = users.user_password

    if not verify_user_credentials(user_email, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Email or Password. Please Try Again",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_access_token = create_access_token_user(data={"sub": user_email})
    return {"Message": "Login Successful", "access_token": user_access_token, "token_type": "bearer"}


@app.delete("/delete_user")
async def delete_user_route(current_user: str = Depends(get_current_user)):
    delete_user(current_user)
    return {"Message": "User Deleted Successfully"}


@app.put("/update_user")
async def update_user_route(updated_user: UserUpdate, current_user: str = Depends(get_current_user)):
    update_user(current_user, updated_user)
    return {"Message": "User Updated Successfully"}


@app.put("/reset_password_user")
async def reset_password_user_route(user_identifier: str, new_password: str):
    conn = engine.connect()
    hashed_password = hash_password(new_password)
    if '@' in user_identifier:
        conn.execute(users.update().where(users.c.user_email == user_identifier).values(
            user_password=hashed_password
        ))
    else:
        conn.execute(users.update().where(users.c.user_id == int(user_identifier)).values(
            user_password=hashed_password
        ))
    conn.commit()
    conn.close()
    return {"Message": "Password Reset Successful"}


@app.put("/change_password_user")
async def change_password_user_route(user_password: UserChangePassword, current_user: str = Depends(get_current_user)):
    change_password_user(current_user, user_password.current_password, user_password.new_password)
    return {"Message": "Password Changed Successfully"}


@app.post("/logout_user")
async def logout_user_route(current_user: str = Depends(get_current_user)):
    # Check if the current user email matches the user identifier
    conn = engine.connect()
    user_query = select(users).where(users.c.user_email == current_user)
    user = conn.execute(user_query).fetchone()
    if not user:
        conn.close()
        return {"Message": "Invalid User"}
    return {"Message": "Logout Successful"}


# Admin Code

admins = Table(
    "admins",
    metadata,
    Column("admin_id", Integer, primary_key=True, index=True),
    Column("admin_name", String(length=255), unique=True, index=True),
    Column("admin_email", String),
    Column("admin_password", String),
    Column("admin_phone", String)
)
metadata.create_all(bind=engine)


class AdminRegistration(BaseModel):
    admin_name: str
    admin_password: str
    admin_email: EmailStr
    admin_phone: str


class AdminLogin(BaseModel):
    admin_email: str
    admin_password: str


class AdminUpdate(BaseModel):
    admin_name: str
    admin_phone: str


class AdminChangePassword(BaseModel):
    current_password: str
    new_password: str


class AdminResetPassword(BaseModel):
    admin_identifier: str
    new_password: str


class AdminResetUserPassword(BaseModel):
    user_identifier: str
    new_password: str


def create_access_token_admin(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_admin_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_email = payload.get("sub")
        if admin_email is None:
            return None
        return admin_email
    except jwt.JWTError:
        return None


def get_current_admin(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_email = payload.get("sub")
        if admin_email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
        return admin_email
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")


def verify_admin_credentials(admin_email: str, admin_password: str):
    conn = engine.connect()
    query = select(admins.c.admin_email, admins.c.admin_password).where(admins.c.admin_email == admin_email)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(admin_password, result[1]):
        return True
    return False


# Database operations
def get_admin(db, admin_email: str):
    conn = db.connect()
    query = select(admins).where(admins.c.admin_email == admin_email)
    result = conn.execute(query).fetchone()
    conn.close()
    return result


def register_admin(admin: AdminRegistration):
    conn = engine.connect()
    hashed_password = hash_password(admin.admin_password)
    conn.execute(admins.insert().values(
        admin_name=admin.admin_name,
        admin_password=hashed_password,
        admin_email=admin.admin_email,
        admin_phone=admin.admin_phone
    ))
    conn.commit()
    conn.close()


def delete_admin(admin_email: str):
    conn = engine.connect()
    conn.execute(admins.delete().where(admins.c.admin_email == admin_email))
    conn.commit()
    conn.close()


def update_admin(admin_email: str, updated_admin: AdminUpdate):
    conn = engine.connect()
    conn.execute(admins.update().where(admins.c.admin_email == admin_email).values(
        admin_name=updated_admin.admin_name,
        admin_phone=updated_admin.admin_phone
    ))
    conn.commit()
    conn.close()


def change_password_admin(admin_email: str, current_password: str, new_password: str):
    conn = engine.connect()
    query = select(admins.c.admin_password).where(admins.c.admin_email == admin_email)
    result = conn.execute(query).fetchone()

    if result:
        current_hashed_password = result[0]
        if password_context.verify(current_password, current_hashed_password):
            hashed_new_password = hash_password(new_password)
            conn.execute(admins.update().where(admins.c.admin_email == admin_email).values(
                admin_password=hashed_new_password
            ))
            conn.commit()
            conn.close()
            return {"Message": "Password Changed Successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Current Password"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not Found"
        )


# Route
@app.post("/register_admin")
async def register_admin_route(admin: AdminRegistration):
    existing_admin = get_admin(engine, admin.admin_email)
    if existing_admin:
        raise HTTPException(status_code=400, detail="Email already Registered")

    register_admin(admin)
    admin_access_token = create_access_token_admin(
        data={"sub": admin.admin_email}
    )
    return {"Message": "This Account Registered Successful", "access_token": admin_access_token, "token_type": "bearer"}


@app.post("/login_admin")
async def login_admin_route(admins: AdminLogin):
    admin_email = admins.admin_email
    admin_password = admins.admin_password

    if not verify_admin_credentials(admin_email, admin_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Email or Password. Please Try Again",
            headers={"WWW-Authenticate": "Bearer"},
        )

    admin_access_token = create_access_token_admin(data={"sub": admin_email})
    return {"Message": "Login Successful", "access_token": admin_access_token, "token_type": "bearer"}


@app.delete("/delete_admin")
async def delete_admin_route(current_admin: str = Depends(get_current_admin)):
    # Check if the current admin email matches the admin identifier
    conn = engine.connect()
    admin_query = select(admins).where(admins.c.admin_email == current_admin)
    admin = conn.execute(admin_query).fetchone()
    if not admin:
        conn.close()
        return {"Message": "Invalid Admin"}
    delete_user(current_admin)
    return {"Message": "Admin Deleted Successfully"}


@app.put("/update_admin")
async def update_admin_route(updated_admin: AdminUpdate, current_admin: str = Depends(get_current_admin)):
    update_admin(current_admin, updated_admin)
    return {"Message": "Admin Updated Successfully"}


@app.post("/reset_password_admin", status_code=status.HTTP_200_OK)
async def reset_password_admin_route(reset_request: AdminResetPassword):
    try:
        conn = engine.connect()
        query = select(admins).where(admins.c.admin_email == reset_request.admin_identifier)
        admin = conn.execute(query).fetchone()
        conn.close()
        if admin:
            hashed_new_password = hash_password(reset_request.new_password)
            conn = engine.connect()
            conn.execute(admins.update().where(admins.c.admin_id == int(admin.admin_id)).values(
                admin_password=hashed_new_password
            ))
            conn.commit()
            conn.close()
            return {"Message": "Password Reset Successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not Found")
    except SQLAlchemyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.put("/change_password_admin")
async def change_password_admin_route(admin_password: AdminChangePassword,
                                      current_admin: str = Depends(get_current_admin)):
    change_password_admin(current_admin, admin_password.current_password, admin_password.new_password)
    return {"Message": "Password Changed Successfully"}


@app.put("/admin_reset_user_password")
async def admin_reset_user_password(reset_request: AdminResetUserPassword,
                                    current_admin: str = Depends(get_current_admin)):
    try:
        # Check if the current admin email matches the admin identifier
        conn = engine.connect()
        admin_query = select(admins).where(admins.c.admin_email == current_admin)
        admin = conn.execute(admin_query).fetchone()
        if not admin:
            conn.close()
            return {"Message": "Invalid Admin"}

        conn = engine.connect()
        query = select(users).where(users.c.user_email == reset_request.user_identifier)
        user = conn.execute(query).fetchone()
        conn.close()
        if user:
            hashed_new_password = hash_password(reset_request.new_password)
            conn = engine.connect()
            conn.execute(users.update().where(users.c.user_id == int(user.user_id)).values(
                user_password=hashed_new_password
            ))
            conn.commit()
            conn.close()
            return {"Message": "Password Reset Successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not Found")
    except SQLAlchemyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/logout_admin")
async def logout_admin_route(current_admin: str = Depends(get_current_admin)):
    # Check if the current admin email matches the admin identifier
    conn = engine.connect()
    admin_query = select(admins).where(admins.c.admin_email == current_admin)
    admin = conn.execute(admin_query).fetchone()
    if not admin:
        conn.close()
        return {"Message": "Invalid Admin"}
    return {"Message": "Logout Successful"}


# Main Load API
def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
