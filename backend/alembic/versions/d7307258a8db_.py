"""empty message

Revision ID: d7307258a8db
Revises: 23815022b25a
Create Date: 2026-07-16 08:17:27.921909

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7307258a8db'
down_revision: Union[str, Sequence[str], None] = '23815022b25a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
