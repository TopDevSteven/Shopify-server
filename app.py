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
redirect_uri = urlencode({"redirect_uri": os.getenv("REDIRECT_URL") + "generate/"})[13:]
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
async def read_root():
    return "Hello"

@app.get("/hello/")
def show():
    return "Hello world"

@app.get("/install/")
async def install(shop: str):
    print(redirect_uri)
    scopes = "read_orders,read_products"
    install_url = f"https://{shop}.myshopify.com/admin/oauth/authorize?client_id={api_key}&scope={scopes}&redirect_uri={redirect_uri}"
    return RedirectResponse(url=install_url)

@app.get("/generate/")
async def generate(request: Request):
    query_params = request.query_params
    hmac = query_params['hmac']
    code  = query_params['code']
    shop  = query_params['shop']
    print(query_params)
    param_name_to_remove = "hmac"
    filtered_params = {key: value for key, value in query_params.items() if key != param_name_to_remove}
    sorted_params = dict(sorted(filtered_params.items()))
    print(sorted_params)
    computed_hmac = HM.new(shared_secret.encode(), urlencode(sorted_params).encode(), hashlib.sha256).hexdigest()
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
        # print(response)
        result = await response.json()
        print(result)
        access_token = result["access_token"]
        return access_token
    else:
        raise HTTPException(status_code=401, detail="HMAC verification failed")

