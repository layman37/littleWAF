#!/usr/bin/env python
#-*- coding: utf-8 -*-


from sqlalchemy import Column
from sqlalchemy.types import CHAR, Integer, String, Text, DATETIME
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


BaseModel = declarative_base()
DB_CONNECT_STRING = 'mysql+mysqldb://waf123:123waf456@localhost/my_waf?charset=utf8'
engine = create_engine(DB_CONNECT_STRING, echo=False)
DB_Session = sessionmaker(bind=engine)


class Block(BaseModel):
    __tablename__ = 'block_behavior'

    TIME = Column(DATETIME(20), primary_key=True)
    IP = Column(CHAR(60), primary_key=True)
    PORT = Column(Integer, primary_key=True)
    TYPE = Column(String(20))
    METHOD = Column(String(20))
    URI = Column(Text)
    INFO = Column(Text)


def init_db():
    BaseModel.metadata.create_all(engine)

# def drop_db():
#     BaseModel.metadata.drop_all(engine)


def log_block(addr,req,Type,src_time):
    
    if Type == "not-white-uri" or Type == "in-black-uri" or Type == "uri" or Type == "arg":
        info = req.uri
    elif Type == "user-agent":
        info = req.headers['user-agent']
    elif Type == "cookie":
        info = req.headers['cookie']
    elif Type == "post-data":
        info = req.body
    try:
        session = DB_Session()
        b = Block(TIME=src_time, IP=addr[0], PORT=addr[1], TYPE=Type, 
                        METHOD=req.method, URI=req.uri, INFO=info)
        session.add(b)
        session.commit()
        session.close()
    except Exception as e:
        print(e)


if __name__ == '__main__':
    init_db()
