"""Many-to-many user/team + per-team notification channels.

Revision ID: 008
Revises: 007
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = '008'
down_revision = '007'


def upgrade():
    # ── 1. Create user_teams junction table ──────────────────────────────
    op.create_table(
        'user_teams',
        sa.Column('user_id', UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('team_id', UUID(as_uuid=True),
                  sa.ForeignKey('teams.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('user_id', 'team_id'),
    )

    # ── 2. Migrate existing single team assignments ───────────────────────
    op.execute("""
        INSERT INTO user_teams (user_id, team_id)
        SELECT id, team_id FROM users WHERE team_id IS NOT NULL
    """)

    # ── 3. Drop team_id from users ────────────────────────────────────────
    op.drop_column('users', 'team_id')

    # ── 4. Add notification URL columns to teams ──────────────────────────
    op.add_column('teams', sa.Column('slack_webhook_url',    sa.Text, nullable=True))
    op.add_column('teams', sa.Column('ms_teams_webhook_url', sa.Text, nullable=True))
    op.add_column('teams', sa.Column('discord_webhook_url',  sa.Text, nullable=True))


def downgrade():
    op.drop_column('teams', 'discord_webhook_url')
    op.drop_column('teams', 'ms_teams_webhook_url')
    op.drop_column('teams', 'slack_webhook_url')

    op.add_column('users', sa.Column('team_id', UUID(as_uuid=True), nullable=True))
    op.execute("""
        UPDATE users u
        SET team_id = (
            SELECT team_id FROM user_teams ut WHERE ut.user_id = u.id LIMIT 1
        )
    """)
    op.drop_table('user_teams')
