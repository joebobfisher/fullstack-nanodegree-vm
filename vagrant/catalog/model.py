from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# Need a table of users
#   id
#   name
#   email (index by this, for people with the same name...)
#   picture
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False, index=True)
    picture = Column(String(250))

# Need a table of categories
#   id
#   name
#   user_id
class Category(Base):
    __tablename__ = 'category'

    name = Column(String(250), nullable=False, primary_key=True)

    # who owns this category?
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return { 'name'     : self.name,
                 'user_id'  : self.user_id }

# Need a table of stuff
#   id
#   name
#   description
#   category
#   user_id
class Stuff(Base):
    __tablename__ = 'stuff'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String)

    # what category does this stuff belong to?
    category_name = Column(String(250), ForeignKey('category.name'))
    category = relationship(Category)

    # who owns this category?
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return { 'id'            : self.id,
                 'name'          : self.name,
                 'description'   : self.description,
                 'category_name' : self.category_name,
                 'user_id'       : self.user_id }

engine = create_engine('sqlite:///stuff.db')
Base.metadata.create_all(engine)
