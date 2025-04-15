# External imports
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# Internal imports
from app.api.v1.database.models import Base
from app.settings import settings
from app.api.logger.logger import get_logger

db_setup_logger = get_logger("app.database.setup")

url = settings.DB_URL

try:
    engine = create_engine(f"{url}", echo=True)
    db_setup_logger.info("Database engine created successfully")
except Exception as e:
    db_setup_logger.error(f"Error creating database engine: {str(e)}")


def init_db():
    """
    Called when main.py is run.
    Creates all tables in the database.
    """
    try:
        db_setup_logger.info("Attempting to create all database tables...")
        Base.metadata.create_all(bind=engine)
        db_setup_logger.info("Database tables created successfully")
    except Exception as e:
        db_setup_logger.error(f"Error creating database tables: {str(e)}")


def get_db():
    """
    Returns a session to the database.
    Used when changes are made to the db during runtime.
    """
    db_setup_logger.debug("Creating new database session")
    try:
        with Session(engine, expire_on_commit=False) as session:
            db_setup_logger.debug("Database session created")
            yield session
            db_setup_logger.debug("Database session closed")
    except Exception as e:
        db_setup_logger.error(f"Error in database session: {str(e)}")
        raise
