from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.blockchain.service import BlockchainService
from app.modules.evidence.service import EvidenceService
from app.schemas.blockchain import (
    BlockchainBlockResponse,
    ChainVerificationResponse,
)


router = APIRouter(
    prefix="/blockchain",
    tags=["Blockchain Audit"]
)


@router.post(
    "/evidence/{evidence_id}",
    response_model=BlockchainBlockResponse,
    status_code=status.HTTP_201_CREATED
)
def add_evidence_to_blockchain(
    evidence_id: int,
    db: Session = Depends(get_db)
):
    evidence = EvidenceService.get_evidence(
        db=db,
        evidence_id=evidence_id
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )

    return BlockchainService.add_evidence(
        db=db,
        evidence=evidence
    )


@router.get(
    "/blocks",
    response_model=list[BlockchainBlockResponse]
)
def get_blockchain(
    db: Session = Depends(get_db)
):
    return BlockchainService.get_chain(db=db)


@router.get(
    "/blocks/{block_id}",
    response_model=BlockchainBlockResponse
)
def get_block(
    block_id: int,
    db: Session = Depends(get_db)
):
    block = BlockchainService.get_block(
        db=db,
        block_id=block_id
    )

    if block is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blockchain block not found"
        )

    return block


@router.get(
    "/verify",
    response_model=ChainVerificationResponse
)
def verify_blockchain(
    db: Session = Depends(get_db)
):
    return BlockchainService.verify_chain(db=db)