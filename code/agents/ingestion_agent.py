"""
============================================================
PHASE 1: Ingestion Agent
============================================================
Responsibility:
    Load evaluation CSV (ID, Context, Code) into SampleRecord objects.

Input:  Path to CSV file
Output: List[SampleRecord]

Design Notes:
    - Handles evaluation mode (ID + Context + Code only)
    - Also handles training mode (all columns present)
    - Robust CSV parsing for embedded newlines and escaped quotes
============================================================
"""

import csv
import logging
from typing import List

from models.data_models import SampleRecord

logger = logging.getLogger(__name__)


class IngestionAgent:
    """
    Agent #1: Data Ingestion
    Loads CSV and produces structured SampleRecord objects.
    Works in both evaluation mode (ID, Context, Code) and
    training mode (all columns including Correct Code, Explanation).
    """

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        logger.info(f"IngestionAgent initialized with path: {csv_path}")

    def load(self) -> List[SampleRecord]:
        """
        Parse the CSV file and return a list of SampleRecord objects.

        Returns:
            List[SampleRecord]: Parsed sample records

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If required columns are missing
        """
        logger.info(f"Loading samples from: {self.csv_path}")
        records: List[SampleRecord] = []

        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = set(reader.fieldnames or [])

            # ── Validate minimum required columns ─────────
            required = {"ID", "Code"}
            if not required.issubset(headers):
                missing = required - headers
                raise ValueError(f"CSV missing required columns: {missing}")

            # ── Detect mode ───────────────────────────────
            has_context = "Context" in headers
            has_correct = "Correct Code" in headers
            has_explanation = "Explanation" in headers

            mode = "evaluation" if not has_correct else "training"
            logger.info(f"  Detected mode: {mode} (columns: {sorted(headers)})")

            for row_num, row in enumerate(reader, start=2):
                try:
                    record = SampleRecord(
                        id=int(row["ID"].strip()),
                        code=row["Code"].strip(),
                        context=row.get("Context", "").strip() if has_context else "",
                        correct_code=row.get("Correct Code", "").strip() if has_correct else "",
                        explanation=row.get("Explanation", "").strip() if has_explanation else "",
                    )
                    records.append(record)
                    logger.debug(f"  Loaded sample ID={record.id}")
                except (ValueError, KeyError) as e:
                    logger.warning(f"  Skipping row {row_num}: {e}")

        logger.info(f"IngestionAgent loaded {len(records)} samples successfully.")
        return records
