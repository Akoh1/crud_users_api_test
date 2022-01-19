"""empty message

Revision ID: 726bcde6a427
Revises: 6c879da75469
Create Date: 2021-12-24 16:20:21.695997

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '726bcde6a427'
down_revision = '6c879da75469'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('jwt_token', sa.String(length=250), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'jwt_token')
    # ### end Alembic commands ###
