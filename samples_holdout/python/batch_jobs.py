"""Nightly batch jobs (held-out smell fixture)."""
import csv
import logging
import time

LOG = logging.getLogger(__name__)
SECONDS_PER_DAY = 86400


def run_job(name, source, target, mode, retries, delay, verbose, results=[]):  # EXPECT: LONG_PARAMETER_LIST, MUTABLE_DEFAULT
    """Run one batch job."""
    for attempt in range(retries):
        try:
            rows = source.read()
            for row in rows:
                if row.valid:
                    if row.kind == "A":
                        if mode == "fast":
                            for cell in row.cells:
                                if cell.dirty:
                                    target.write(cell)  # EXPECT: DEEP_NESTING
            return True
        except Exception:  # EXPECT: BROAD_EXCEPT
            LOG.warning("attempt %d failed", attempt)
            time.sleep(delay)
    return False


def stale(job):
    """Is the job older than a day?"""
    elapsed = time.time() - job.started
    return elapsed > 86400  # EXPECT: MAGIC_NUMBER


def stale_ok(job):
    """Is the job older than a day (named constant)?"""
    return time.time() - job.started > SECONDS_PER_DAY


def read_users(path):
    """Read users from a CSV file."""
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cleanup(items):
    """Remove stale items."""
    for item in items:
        try:
            item.remove()
        except OSError:  # EXPECT: EMPTY_EXCEPT
            pass


def has_value(x):
    """Check for a value."""
    return x != None  # EXPECT: COMPARE_NONE
