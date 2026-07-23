"""Initial URLCHEAKER schema.

Revision ID: 0001
Revises:
Create Date: 2026-07-23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("display_url", sa.Text(), nullable=False),
        sa.Column("normalized_url_hash", sa.String(length=64), nullable=False),
        sa.Column("registrable_domain", sa.String(length=253), nullable=False),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("threat_type", sa.String(length=64), nullable=True),
        sa.Column("malicious_probability", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("decision_source", sa.String(length=32), nullable=False),
        sa.Column("requires_analyst_review", sa.Boolean(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("feed_matches", sa.JSON(), nullable=False),
        sa.Column("model_version", sa.String(length=128), nullable=False),
        sa.Column("dataset_version", sa.String(length=128), nullable=False),
        sa.Column("model_backend", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyses_classification", "analyses", ["classification"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_index("ix_analyses_normalized_url_hash", "analyses", ["normalized_url_hash"])
    op.create_index("ix_analyses_registrable_domain", "analyses", ["registrable_domain"])

    op.create_table(
        "analyst_verdicts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("threat_type", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyst_verdicts_analysis_id", "analyst_verdicts", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_analyst_verdicts_analysis_id", table_name="analyst_verdicts")
    op.drop_table("analyst_verdicts")
    op.drop_index("ix_analyses_registrable_domain", table_name="analyses")
    op.drop_index("ix_analyses_normalized_url_hash", table_name="analyses")
    op.drop_index("ix_analyses_created_at", table_name="analyses")
    op.drop_index("ix_analyses_classification", table_name="analyses")
    op.drop_table("analyses")
