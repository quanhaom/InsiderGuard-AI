from fastapi import APIRouter

router = APIRouter(
    prefix="/collector",
    tags=["Collector"]
)