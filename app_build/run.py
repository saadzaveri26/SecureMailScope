"""Dev launcher:  python run.py  ->  http://localhost:8000/docs"""
import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=os.getenv("SMS_HOST", "0.0.0.0"),
                port=int(os.getenv("SMS_PORT", "8000")), reload=bool(os.getenv("SMS_RELOAD")))
