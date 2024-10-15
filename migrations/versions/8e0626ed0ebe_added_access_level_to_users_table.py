"""Added access_level to users table

Revision ID: 8e0626ed0ebe
Revises: dcfa167aa33c
Create Date: 2024-10-15 13:46:06.617848

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8e0626ed0ebe"
down_revision = "dcfa167aa33c"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "access_level",
                sa.String(length=16),
                nullable=False,
                server_default="basic",
            )
        )

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("access_level")

    # ### end Alembic commands ###