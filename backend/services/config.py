"""Centralized runtime configuration constants."""

# ── code_parser limits ──
MAX_FILE_SIZE = 500 * 1024        # 500KB per source file
MAX_FILES = 500                    # max files to scan per project
TOTAL_CHARS_LIMIT = 2_000_000     # total character budget
CACHE_SCHEMA_VERSION = 7
OVERSIZED_HEAD_CHARS = 1400
OVERSIZED_TAIL_CHARS = 1000
OVERSIZED_MAX_WINDOWS = 6
OVERSIZED_WINDOW_RADIUS = 18

# ── LLM client ──
DEFAULT_LLM_TIMEOUT_SECONDS = 180.0

# ── audit worker ──
WORKER_POLL_INTERVAL_SECONDS = 2.0
WORKER_TASK_TIMEOUT_SECONDS = 3600

# ── multi-agent ──
MAX_CONCURRENT_AGENTS = 3
