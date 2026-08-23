"""add outbound webhooks + delivery log (Phase 19)

Revision ID: c3f8a91d2e47
Revises: 1da1e657ca46
Create Date: 2026-08-23

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3f8a91d2e47'
down_revision = '1da1e657ca46'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('outbound_webhooks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('org_id', sa.Integer(), nullable=True),
    sa.Column('created_by_user_id', sa.Integer(), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('url', sa.String(length=2048), nullable=False),
    sa.Column('secret', sa.String(length=64), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('webhook_deliveries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('webhook_id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('response_code', sa.Integer(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['webhook_id'], ['outbound_webhooks.id'], ),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_webhook_deliveries_webhook_id_id', 'webhook_deliveries', ['webhook_id', 'id'])


def downgrade():
    op.drop_index('ix_webhook_deliveries_webhook_id_id', table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')
    op.drop_table('outbound_webhooks')
