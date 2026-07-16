"""test migration

Revision ID: 4947349bbaed
Revises: 01a101271f56
Create Date: 2026-07-16 08:01:13.843444

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4947349bbaed'
down_revision: Union[str, Sequence[str], None] = '01a101271f56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
