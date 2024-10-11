EXTENSION = pgton            # Name of the extension
MODULES = pgton              # The C file to compile
DATA = pgton--0.1.sql        # SQL script to install the extension
PG_CONFIG = pg_config        # Use pg_config to locate PostgreSQL installation

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
