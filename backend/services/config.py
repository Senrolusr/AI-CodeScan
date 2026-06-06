"""Centralized runtime configuration constants."""

# ── code_parser limits ──
MAX_FILE_SIZE = 500 * 1024        # 500KB per source file
MAX_TREE_FILES = 10_000           # max source/config files to index in the project tree
MAX_AUDIT_SOURCE_FILES = 1_200    # max prioritized files to read into audit chunks
MAX_CODE_CHUNKS = 2_000           # max chunks cached for staged audit selection
TOTAL_CHARS_LIMIT = 2_000_000     # total character budget
CACHE_SCHEMA_VERSION = 8
OVERSIZED_HEAD_CHARS = 1400
OVERSIZED_TAIL_CHARS = 1000
OVERSIZED_MAX_WINDOWS = 6
OVERSIZED_WINDOW_RADIUS = 18

# ── LLM client ──
DEFAULT_LLM_TIMEOUT_SECONDS = 180.0

# ── audit worker ──
WORKER_POLL_INTERVAL_SECONDS = 2.0
WORKER_TASK_TIMEOUT_SECONDS = 7200

# ── multi-agent ──
MAX_CONCURRENT_AGENTS = 3
