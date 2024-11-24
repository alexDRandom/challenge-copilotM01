from fastapi import FastAPI, HTTPException, Query
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

SECRET_KEY = "your-secret-key"  # Replace with a strong, randomly generated secret
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_db = {"users": {}}

app = FastAPI()

class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int


class User(BaseModel):
    """
    Represents a user with a username and password.
    
    This model is used for user registration and authentication in the application.
    """
    username: str
    password: str


@app.post("/register")
async def register(user: User):
    """
    Registers a new user in the application's fake database.
    
    If the provided username already exists in the database, an HTTPException with a 400 
    Bad Request status code is raised with the detail "User already exists".
    
    Otherwise, the provided password is hashed using the bcrypt algorithm and stored in the fake database
    along with the username. A success message is returned.
    """
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = pwd_context.hash(user.password)
    fake_db["users"][user.username] = {"password": hashed_password}
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(user: User):
    """
    Authenticates a user and generates an access token.
    
    If the provided username and password are valid, an access token is generated using the `SECRET_KEY`
    and the user's username. The access token is returned in the response.
    
    If the provided username or password is invalid, an `HTTPException` with a 401 Unauthorized 
    status code is raised with the detail "Invalid credentials".
    """
    db_user = fake_db["users"].get(user.username)
    if not db_user or not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = jwt.encode({"username": user.username}, SECRET_KEY, algorithm="HS256")
    return {"access_token": access_token}


def verify_token(token: str):
    """
    Verifies the provided JWT token by decoding it with the `SECRET_KEY`. If the token is valid,
    the decoded payload is returned. If the token is invalid, an `HTTPException` with a 401 
    Unauthorized status code and the detail "Invalid token" is raised.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/bubble-sort")
async def bubble_sort(payload: Payload, token: str = ""):  # Type hint added
    """
    Sorts a list of numbers using the bubble sort algorithm.
    
    The function takes a `Payload` object containing a list of numbers, and an optional `token` 
    parameter for authentication. If the provided token is invalid, an `HTTPException` with a 401
    Unauthorized status code is raised.
    
    The function sorts the list of numbers in-place using the bubble sort algorithm, and returns a 
    dictionary containing the sorted list of numbers.
    """
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")

    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    return {"numbers": numbers}


@app.post("/filter-even")
async def filter_even(payload: Payload, token: str = ""):
    """
    Filters a list of numbers to return only the even numbers.
    
    The function takes a `Payload` object containing a list of numbers, and an optional `token`
    parameter for authentication. If the provided token is invalid, an `HTTPException` with a 401 
    Unauthorized status code is raised.
    
    The function returns a dictionary containing a list of the even numbers from the input list.
    """    
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"even_numbers": [n for n in payload.numbers if n % 2 == 0]}


@app.post("/sum-elements")
async def sum_elements(payload: Payload, token: str = ""):
    """
    Calculates the sum of a list of numbers.
    
    The function takes a `Payload` object containing a list of numbers, and an optional `token` 
    parameter for authentication. If the provided token is invalid, an `HTTPException` with a 401 
    Unauthorized status code is raised.
    
    The function returns a dictionary containing the sum of the numbers in the input list.
    """
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"sum": sum(payload.numbers)}


@app.post("/max-value")
async def max_value(payload: Payload, token: str = ""):
    """
    Finds the maximum value in a list of numbers.
    
    The function takes a `Payload` object containing a list of numbers, and an optional `token` 
    parameter for authentication. If the provided token is invalid, an `HTTPException` with a 401
    Unauthorized status code is raised.
    
    The function returns a dictionary containing the maximum value from the input list of numbers.
    """
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"max": max(payload.numbers)}


@app.post("/binary-search")
async def binary_search(payload: BinarySearchPayload, token: str = ""):
    """
    Performs a binary search for a target value in a sorted list of numbers. If the target is found, 
    returns a dictionary with `found` set to `True` and the `index` of the target. If the target is not found, 
    returns a dictionary with `found` set to `False` and the `index` set to `-1`.
    
    The function takes a `BinarySearchPayload` object containing the `numbers` list and the `target` 
    value to search for, as well as an optional `token` parameter for authentication. 
    If the provided token is invalid, an `HTTPException` with a 401 Unauthorized status code is raised.
    """
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")

    numbers = payload.numbers
    target = payload.target
    low = 0
    high = len(numbers) - 1
    while low <= high:
        mid = (low + high) // 2
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return {"found": False, "index": -1}