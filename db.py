from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import hashlib
import os
from urllib.parse import urlparse

Base = declarative_base()

class Source(Base):
    __tablename__ = 'sources'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(2000), nullable=False, index=True)
    domain = Column(String(255), index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_checked = Column(DateTime, default=datetime.utcnow)
    is_benign = Column(Boolean, default=None, nullable=True)  # True: benign, False: malicious, None: unknown
    status_code = Column(Integer)
    content_type = Column(String(255))
    
    indicators = relationship("Indicator", back_populates="source")
    
    @classmethod
    def get_or_create(cls, session, url, **kwargs):
        instance = session.query(cls).filter_by(url=url).first()
        if instance:
            return instance, False
        else:
            domain = urlparse(url).netloc
            instance = cls(url=url, domain=domain, **kwargs)
            session.add(instance)
            return instance, True

class Indicator(Base):
    __tablename__ = 'indicators'
    
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey('sources.id'))
    snippet_hash = Column(String(64), index=True)
    snippet_text = Column(Text, nullable=False)
    stage = Column(Integer, default=1)
    detection_method = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_analyzed = Column(Boolean, default=False)
    analysis_notes = Column(Text)
    
    source = relationship("Source", back_populates="indicators")
    
    @classmethod
    def create_from_snippet(cls, session, source, snippet_text, detection_method, stage=1):
        snippet_hash = hashlib.sha256(snippet_text.encode('utf-8')).hexdigest()
        existing = session.query(cls).filter_by(snippet_hash=snippet_hash).first()
        if existing:
            return existing, False
            
        indicator = cls(
            source=source,
            snippet_hash=snippet_hash,
            snippet_text=snippet_text[:10000],  # Limit size
            detection_method=detection_method,
            stage=stage
        )
        session.add(indicator)
        return indicator, True

def init_db(db_path='socgholish_indicators.db'):
    """Initialize the database and create tables if they don't exist."""
    from sqlalchemy import inspect
    
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or '.', exist_ok=True)
    db_url = f'sqlite:///{db_path}'
    engine = create_engine(db_url)
    
    # Create all tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Set up a session
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Check if we need to add the last_checked column
    inspector = inspect(engine)
    if 'sources' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('sources')]
        if 'last_checked' not in columns:
            session.execute('ALTER TABLE sources ADD COLUMN last_checked DATETIME')
        if 'is_benign' not in columns:
            session.execute('ALTER TABLE sources ADD COLUMN is_benign BOOLEAN')
        session.commit()
    
    return session

def get_db_session():
    """Get a database session."""
    db_path = os.environ.get('SGH_DB_PATH', 'socgholish_indicators.db')
    return init_db(db_path)