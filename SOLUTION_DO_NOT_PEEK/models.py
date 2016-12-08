import os

import sqlalchemy
from sqlalchemy.ext import declarative


db_file = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                       "..",
                                       "iostat.sqlite"))
db_path = "sqlite:///%s" % db_file

Base = declarative.declarative_base()


class User(Base):
    __tablename__ = 'users'

    username = sqlalchemy.Column(sqlalchemy.String, primary_key=True)
    password = sqlalchemy.Column(sqlalchemy.String)
    fullname = sqlalchemy.Column(sqlalchemy.String)
    admin = sqlalchemy.Column(sqlalchemy.Boolean)

    def __repr__(self):
        return "<User(username='%s', fullname='%s', admin=%s)>" % (
            self.username, self.fullname, self.admin)

if __name__ == "__main__":
    engine = sqlalchemy.create_engine(db_path, echo=True)
    Base.metadata.create_all(engine)
