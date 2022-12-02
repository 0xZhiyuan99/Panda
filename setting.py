from algosdk.v2client import algod

#### PLEASE SET THESE VARIABLES MANUALLY! ####
#algod_address = "http://localhost:8080"
#algod_token = "a10bb2385b5f59e6faea30a71d1ec373547fc84b639209d89a23fe7109542d86"
algod_address = "http://localhost:4001"
algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#algod_address = "http://47.93.240.23:2398"
#algod_token = "0e3db4752c9669a6da25d99aafa662801f71f8bbbe39842545fc025b14a3b39c"
algod_client = algod.AlgodClient(algod_token, algod_address)

DB_PATH = './db/'
ALGO_DB = "algorand"
ALGO_USER = "algorand"
ALGO_PWD = "daige@@1999"
#ALGO_HOST = "47.93.240.23"
#ALGO_PORT = "57124"
ALGO_HOST = "127.0.0.1"
ALGO_PORT = "5432"

PROCESS_COUNT = 40
WORKLOAD = 10
##############################################


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