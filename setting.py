#algod_address = "http://localhost:4001"
#algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
algod_address = ""
algod_token = ""
DB_PATH = ""
ALGO_DB = ""
ALGO_USER = ""
ALGO_PWD = ""
ALGO_HOST = ""
ALGO_PORT = ""

algod_client = None

# Used for large-scale evaluation
PROCESS_COUNT = 64
WORKLOAD = 10

sender_address = "\x50" * 32

# Print debug message
DEBUG_MODE = False

# Input TEAL file name
SOURCE_FILENAME = ""

APPLICATION_ID = 0

# Maximum block stack depth for symbolic execution
BLOCK_SEARCH_DEPTH = 50

# Maximum basic block access count
BLOCK_ACCESS_COUNT = 3

# Timeout for z3 in ms
Z3_TIMEOUT = 30000

# Timeout to run symbolic execution (in secs)
GLOBAL_TIMEOUT = 900

MAXIMUM_COST = 0

# The type of the input file
IS_SMART_CONTRACT = False
IS_LOGIC_SIGNATURE = False

# Max depth of the Algorand runtime stack
MAX_STACK_DEPTH = 1000

# Take the signature validator into consideration
INCLUDE_APP = False

# Take the global state of the validator as concrete value
LOAD_STATE = False

# Bypass the validator if there is no constraint on OnCompletion
BYPASS_VALIDATOR = False

# The default detection rule set to be used
DETECTION_RULE_SET = "rule1"

