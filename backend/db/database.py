"""
NeuroSploit v3 - Database Configuration
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from backend.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all models"""
    pass


# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

# Create async session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Alias for background tasks
async_session_factory = async_session_maker


async def get_db() -> AsyncSession:
    """Dependency to get database session"""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def _run_migrations(conn):
    """Run schema migrations to add missing columns"""
    try:
        # Check and add duration column to scans table
        result = await conn.execute(text("PRAGMA table_info(scans)"))
        columns = [row[1] for row in result.fetchall()]

        if "duration" not in columns:
            logger.info("Adding 'duration' column to scans table...")
            await conn.execute(text("ALTER TABLE scans ADD COLUMN duration INTEGER"))

        # Check and add columns to reports table
        result = await conn.execute(text("PRAGMA table_info(reports)"))
        columns = [row[1] for row in result.fetchall()]

        if columns:  # Table exists
            if "auto_generated" not in columns:
                logger.info("Adding 'auto_generated' column to reports table...")
                await conn.execute(text("ALTER TABLE reports ADD COLUMN auto_generated BOOLEAN DEFAULT 0"))

            if "is_partial" not in columns:
                logger.info("Adding 'is_partial' column to reports table...")
                await conn.execute(text("ALTER TABLE reports ADD COLUMN is_partial BOOLEAN DEFAULT 0"))

        # Check and add columns to vulnerabilities table
        result = await conn.execute(text("PRAGMA table_info(vulnerabilities)"))
        columns = [row[1] for row in result.fetchall()]

        if columns:  # Table exists
            if "test_id" not in columns:
                logger.info("Adding 'test_id' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN test_id VARCHAR(36)"))

            if "poc_parameter" not in columns:
                logger.info("Adding 'poc_parameter' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN poc_parameter VARCHAR(500)"))

            if "poc_evidence" not in columns:
                logger.info("Adding 'poc_evidence' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN poc_evidence TEXT"))

            if "screenshots" not in columns:
                logger.info("Adding 'screenshots' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN screenshots JSON DEFAULT '[]'"))

            if "url" not in columns:
                logger.info("Adding 'url' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN url TEXT"))

            if "parameter" not in columns:
                logger.info("Adding 'parameter' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN parameter VARCHAR(500)"))

            if "validation_status" not in columns:
                logger.info("Adding 'validation_status' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN validation_status VARCHAR(20) DEFAULT 'ai_confirmed'"))

            if "ai_rejection_reason" not in columns:
                logger.info("Adding 'ai_rejection_reason' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN ai_rejection_reason TEXT"))

            if "poc_code" not in columns:
                logger.info("Adding 'poc_code' column to vulnerabilities table...")
                await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN poc_code TEXT"))

        # Check if agent_tasks table exists
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_tasks'")
        )
        if not result.fetchone():
            logger.info("Creating 'agent_tasks' table...")
            await conn.execute(text("""
                CREATE TABLE agent_tasks (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL,
                    task_type VARCHAR(50) NOT NULL,
                    task_name VARCHAR(255) NOT NULL,
                    description TEXT,
                    tool_name VARCHAR(100),
                    tool_category VARCHAR(100),
                    status VARCHAR(20) DEFAULT 'pending',
                    started_at DATETIME,
                    completed_at DATETIME,
                    duration_ms INTEGER,
                    items_processed INTEGER DEFAULT 0,
                    items_found INTEGER DEFAULT 0,
                    result_summary TEXT,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_agent_tasks_scan_id ON agent_tasks(scan_id)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status)"))

        # Check if vulnerability_tests table exists
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerability_tests'")
        )
        if not result.fetchone():
            logger.info("Creating 'vulnerability_tests' table...")
            await conn.execute(text("""
                CREATE TABLE vulnerability_tests (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL,
                    endpoint_id VARCHAR(36),
                    vulnerability_type VARCHAR(100) NOT NULL,
                    payload TEXT,
                    request_data JSON DEFAULT '{}',
                    response_data JSON DEFAULT '{}',
                    is_vulnerable BOOLEAN DEFAULT 0,
                    confidence FLOAT,
                    evidence TEXT,
                    tested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL
                )
            """))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_vulnerability_tests_scan_id ON vulnerability_tests(scan_id)"))

        # Check if vuln_lab_challenges table exists
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_lab_challenges'")
        )
        if not result.fetchone():
            logger.info("Creating 'vuln_lab_challenges' table...")
            await conn.execute(text("""
                CREATE TABLE vuln_lab_challenges (
                    id VARCHAR(36) PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    challenge_name VARCHAR(255),
                    vuln_type VARCHAR(100) NOT NULL,
                    vuln_category VARCHAR(50),
                    auth_type VARCHAR(20),
                    auth_value TEXT,
                    status VARCHAR(20) DEFAULT 'pending',
                    result VARCHAR(20),
                    agent_id VARCHAR(36),
                    scan_id VARCHAR(36),
                    findings_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    findings_detail JSON DEFAULT '[]',
                    started_at DATETIME,
                    completed_at DATETIME,
                    duration INTEGER,
                    notes TEXT,
                    logs JSON DEFAULT '[]',
                    endpoints_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_lab_status ON vuln_lab_challenges(status)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_vuln_lab_vuln_type ON vuln_lab_challenges(vuln_type)"))
        else:
            # Migrate existing table - add new columns if missing
            result = await conn.execute(text("PRAGMA table_info(vuln_lab_challenges)"))
            columns = [row[1] for row in result.fetchall()]
            if "logs" not in columns:
                await conn.execute(text("ALTER TABLE vuln_lab_challenges ADD COLUMN logs JSON DEFAULT '[]'"))
            if "endpoints_count" not in columns:
                await conn.execute(text("ALTER TABLE vuln_lab_challenges ADD COLUMN endpoints_count INTEGER DEFAULT 0"))

        logger.info("Database migrations completed")
    except Exception as e:
        logger.warning(f"Migration check failed (may be normal on first run): {e}")


async def init_db():
    """Initialize database tables and run migrations"""
    async with engine.begin() as conn:
        # Create all tables from models
        await conn.run_sync(Base.metadata.create_all)
        # Run migrations to add any missing columns
        await _run_migrations(conn)


async def close_db():
    """Close database connection"""
    await engine.dispose()
