"""Code parser facade (M3b split)."""

from __future__ import annotations

from services.code_parser_pkg._constants import *  # noqa: F401,F403
from services.code_parser_pkg._utils import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403
from services.code_parser_pkg.files import *  # noqa: F401,F403
from services.code_parser_pkg.pre_discovery import *  # noqa: F401,F403
from services.code_parser_pkg.rules import *  # noqa: F401,F403
from services.code_parser_pkg.chunks import *  # noqa: F401,F403
from services.code_parser_pkg.routes_extract import *  # noqa: F401,F403
from services.code_parser_pkg.routes_resolve import *  # noqa: F401,F403
from services.code_parser_pkg.routes import *  # noqa: F401,F403
from services.code_parser_pkg.source_sink import *  # noqa: F401,F403
from services.code_parser_pkg.project import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)
