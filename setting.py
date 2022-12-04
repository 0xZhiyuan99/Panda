from algosdk.v2client import algod

#### PLEASE SET THESE VARIABLES MANUALLY! ####
algod_address = "http://39.96.213.29:43588"
algod_token = "38813a6a351f19dfee478e732eb8d6176fe9d7b1882b662205b370b55f34ada3"
#algod_address = "http://localhost:4001"
#algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
algod_client = algod.AlgodClient(algod_token, algod_address)

DB_PATH = './db/'
ALGO_DB = "postgres"
ALGO_USER = "algorand"
ALGO_PWD = "daige@@1999"
ALGO_HOST = "39.96.213.29"
ALGO_PORT = "57124"
##############################################

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