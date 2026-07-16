"""add incident assignment

Revision ID: 23815022b25a
Revises: 4947349bbaed
Create Date: 2026-07-16 08:01:40.464654

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '23815022b25a'
down_revision: Union[str, Sequence[str], None] = '4947349bbaed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
