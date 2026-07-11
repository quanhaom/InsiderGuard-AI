from datetime import datetime

from pydantic import BaseModel


class BlockchainBlockResponse(BaseModel):
    id: int
    block_index: int
    evidence_id: int
    evidence_hash: str
    previous_hash: str
    block_hash: str
    nonce: int
    created_at: datetime


class BlockVerificationResponse(BaseModel):
    block_id: int
    block_index: int
    evidence_valid: bool
    block_hash_valid: bool
    previous_hash_valid: bool
    is_valid: bool


class ChainVerificationResponse(BaseModel):
    total_blocks: int
    valid_blocks: int
    invalid_blocks: int
    is_valid: bool
    results: list[BlockVerificationResponse]