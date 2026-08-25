"""add payload_format to OutboundWebhook + attempt_number to WebhookDelivery (Phase 25)

Revision ID: a1b2c3d4e5f6
Revises: c3f8a91d2e47
Create Date: 2026-08-24

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'c3f8a91d2e47'
branch_labels = None
depends_on = None


def upgrade():
    # INTG-02: payload_format — "default" (raw JSON) or "splunk_hec" (HEC wrapper)
    op.add_column('outbound_webhooks',
        sa.Column('payload_format', sa.String(length=32), server_default="default", nullable=False))
    # INTG-03: attempt_number — which try of the bounded retry this row represents
    op.add_column('webhook_deliveries',
        sa.Column('attempt_number', sa.Integer(), server_default="1", nullable=False))


def downgrade():
    op.drop_column('webhook_deliveries', 'attempt_number')
    op.drop_column('outbound_webhooks', 'payload_format')
