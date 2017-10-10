import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

# for the users stuff
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer,
                         BadSignature, SignatureExpired)

# encoding stuff

import codecs
sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))
Base = declarative_base()


class User(Base):
    """Class for Users"""
    __tablename__ = 'user'

    name = Column(String(80), nullable=False)
    email = Column(String, nullable=False)
    picture = Column(String)
    username = Column(String(32))
    id = Column(Integer, primary_key=True)
    password = Column(String(12))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Marca(Base):
    """Class for marcas"""
    __tablename__ = 'marca'

    name = Column(
        String(80), nullable=False, unique=True)
    id = Column(
        Integer, primary_key=True)
    description = Column(
        String(250))
    picture = Column(String)
    user_id = Column(
        Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        # Returns object data in easily serializeable format
        return {
            'name': self.name,
            'id': self.id,
            'description': self.description,
        }


class ItemMarca(Base):
    """Class for Marca Items"""
    __tablename__ = 'item_marca'

    name = Column(
        String(80), nullable=False)
    id = Column(
        Integer, primary_key=True)
    peca = Column(
        String(250))
    description = Column(
        String(1000))
    price = Column(
        String(8))
    picture = Column(String(200))
    size = Column(String(10))
    quantityP = Column(Integer)
    quantityM = Column(Integer)
    quantityG = Column(Integer)
    marca_id = Column(
        Integer, ForeignKey('marca.id'))
    user_id = Column(
        Integer, ForeignKey('user.id'))
    marca = relationship(Marca)
    user = relationship(User)

    @property
    def serialize(self):
        # Returns object data in easily serializeable format
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'course': self.course,
        }


"""

Insert at the end of the file!

"""

engine = create_engine(
    'postgresql:///estile')

Base.metadata.create_all(engine)
