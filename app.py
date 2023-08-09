from fastapi import FastAPI, Request, HTTPException
from starlette.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import hashlib
import httpx
import hmac as HM
from urllib.parse import urlencode

load_dotenv()

redirect_uri = urlencode({'redirect_uri': os.getenv("REDIRECT_URL") + "generate/"})[13:]

api_key = os.getenv("API_KEY")
shared_secret = os.getenv("SECRET_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    uri = "https://translate.google.com/"
    return RedirectResponse(url=uri)

@app.get("/hello/")
def show():
    return "Hello world"

@app.get("/install/")
async def install(shop: str):
    scopes = "read_orders,read_products"
    install_url = f"https://{shop}.myshopify.com/admin/oauth/authorize?client_id={api_key}&scope={scopes}&redirect_uri={redirect_uri}"
    return RedirectResponse(url=install_url)



@app.get("/generate/")
async def generate(shop: str, hmac: str, code: str):
    print(f"shop : {shop}")
    print(f"hmac : {hmac}")
    print(f"code : {code}")

    params = {
        "shop": shop,
        "code": code,
    }
    
    computed_hmac = HM.new(shared_secret.encode(), urlencode(params).encode(), hashlib.sha256).hexdigest()
    print(computed_hmac)
    if HM.compare_digest(hmac, computed_hmac):
        query = {
            "client_id": api_key,
            "client_secret": shared_secret,
            "code": code,
        }
        access_token_url = f"https://{shop}/admin/oauth/access_token"
        async with httpx.AsyncClient() as client:
            response = await client.post(access_token_url, data=query)

        result = response.json()
        access_token = result["access_token"]
        return access_token
    else:
        raise HTTPException(status_code=401, detail="HMAC verification failed")


