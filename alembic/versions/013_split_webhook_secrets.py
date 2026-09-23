"""013 — Split the webhook secret into an inbound token hash and a signing secret

One column did two jobs, with the same value:

  * inbound authentication for POST /api/inbound/{team_id}, which can rotate
    a team's API key and returns the new key in its response;
  * the HMAC key for signing outbound event deliveries.

Because it was one value, and stored in the clear, anyone able to read the
webhooks table could authenticate to the inbound endpoint, rotate a key and
receive the new one - a read of the database became access to the secrets the
key can fetch.

They are now separate:

  inbound_secret_hash  SHA-256 of the inbound token; the token itself is shown
                       once at creation and is not recoverable from the row.
  signing_secret       the HMAC key. Necessarily recoverable, because signing
                       needs it, but it only permits forging events to the
                       team's own endpoint - it no longer mints credentials.

Existing rows are backfilled so current integrations keep working: today's
secret becomes the signing secret, and its hash becomes the inbound token
hash, so the token a CI pipeline already holds still authenticates until it
is rotated.

Revision ID: 013
Revises: 012
"""

import sqlalchemy as sa
from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("webhooks", sa.Column("inbound_secret_hash", sa.Text(), nullable=True))
    op.add_column("webhooks", sa.Column("signing_secret", sa.Text(), nullable=True))
    op.execute("""
        UPDATE webhooks
           SET signing_secret      = secret,
               inbound_secret_hash = encode(digest(secret, 'sha256'), 'hex')
         WHERE secret IS NOT NULL
    """)
    op.drop_column("webhooks", "secret")


def downgrade():
    op.add_column("webhooks", sa.Column("secret", sa.Text(), nullable=True))
    # The inbound token cannot be recovered from its hash; the signing secret
    # is the only value that can be put back.
    op.execute("UPDATE webhooks SET secret = signing_secret")
    op.drop_column("webhooks", "signing_secret")
    op.drop_column("webhooks", "inbound_secret_hash")
