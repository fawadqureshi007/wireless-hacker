#!/usr/bin/env python3
"""Advanced logging setup for SUDOIT framework."""

import sys
import logging
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler

def setup_logging(log_dir: Path, log_level: str = "INFO") -> logging.Logger:
    """Configure professional logging with rotation."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"sudoit_{datetime.now():%Y%m%d_%H%M%S}.log"
    
    logger = logging.getLogger("SUDOIT")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation (10MB max, 5 backups)
    fh = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=5)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(ch)
    
    return logger

def get_logger(name: str = "SUDOIT") -> logging.Logger:
    """Get a logger by name."""
    return logging.getLogger(name)
