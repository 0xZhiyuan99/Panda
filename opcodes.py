
# opcodes[name] has a list of [cost, whether support application mode, whether support signature mode,
# number of parameters, opcode handle function]
import executor
import runtime
import logging

log = logging.getLogger(__name__)

COST = 0
APPLICATION_MODE = 1
SIGNATURE_MODE = 2
PARAMS = 3
HANDLE = 4

# We support 108/139 opcodes
OPCODES = {
    "debug_display_global_state": [0, 1, 1, 0, executor.debug_display_global_state], # Used for debugging
    "debug_display_stack": [0, 1, 1, 0, executor.debug_display_stack], # Used for debugging
    "debug_exit": [0, 1, 1, 0, executor.debug_exit], # Used for debugging
    "int": [1, 1, 1, 1, executor.int_handle],
    "byte": [1, 1, 1, 1, executor.byte_handle],
    "addr": [1, 1, 1, 1, executor.addr_handle],
    "intcblock": [1, 1, 1, -1, executor.intcblock_handle],
    "bytecblock": [1, 1, 1, -1, executor.bytecblock_handle],
    "err": [1, 1, 1, 0, executor.err_handle],
    "sha256": [35, 1, 1, 0, executor.sha256_handle],
    "keccak256": [130, 1, 1, 0, executor.keccak256_handle],
    "sha512_256": [45, 1, 1, 0, executor.sha512_256_handle],
    "+": [1, 1, 1, 0, executor.add_handle],
    "-": [1, 1, 1, 0, executor.sub_handle],
    "/": [1, 1, 1, 0, executor.div_handle],
    "*": [1, 1, 1, 0, executor.mul_handle],
    "<": [1, 1, 1, 0, executor.LT_handle],
    ">": [1, 1, 1, 0, executor.GT_handle],
    "<=": [1, 1, 1, 0, executor.LE_handle],
    ">=": [1, 1, 1, 0, executor.GE_handle],
    "&&": [1, 1, 1, 0, executor.logic_and_handle],
    "||": [1, 1, 1, 0, executor.logic_or_handle],
    "==": [1, 1, 1, 0, executor.EQ_handle],
    "!=": [1, 1, 1, 0, executor.NEQ_handle],
    "!": [1, 1, 1, 0, executor.test_zero_handle],
    "len": [1, 1, 1, 0, executor.len_handle],
    "itob": [1, 1, 1, 0, executor.itob_handle],
    "btoi": [1, 1, 1, 0, executor.btoi_handle],
    "%": [1, 1, 1, 0, executor.rem_handle],
    "|": [1, 1, 1, 0, executor.bit_or_handle],
    "&": [1, 1, 1, 0, executor.bit_and_handle],
    "^": [1, 1, 1, 0, executor.bit_xor_handle],
    "~": [1, 1, 1, 0, executor.bit_not_handle],
    "intc": [1, 1, 1, 1, executor.intc_handle],
    "intc_0": [1, 1, 1, 0, executor.intc_0_handle],
    "intc_1": [1, 1, 1, 0, executor.intc_1_handle],
    "intc_2": [1, 1, 1, 0, executor.intc_2_handle],
    "intc_3": [1, 1, 1, 0, executor.intc_3_handle],
    "bytec": [1, 1, 1, 1, executor.bytec_handle],
    "bytec_0": [1, 1, 1, 0, executor.bytec_0_handle],
    "bytec_1": [1, 1, 1, 0, executor.bytec_1_handle],
    "bytec_2": [1, 1, 1, 0, executor.bytec_2_handle],
    "bytec_3": [1, 1, 1, 0, executor.bytec_3_handle],
    "arg": [1, 0, 1, 1, executor.arg_handle],
    "arg_0": [1, 0, 1, 0, executor.arg_i_handle],
    "arg_1": [1, 0, 1, 0, executor.arg_i_handle],
    "arg_2": [1, 0, 1, 0, executor.arg_i_handle],
    "arg_3": [1, 0, 1, 0, executor.arg_i_handle],
    "txn": [1, 1, 1, 1, executor.txn_handle],
    "global": [1, 1, 1, 1, executor.global_handle],
    "gtxn": [1, 1, 1, 2, executor.gtxn_handle],
    "load": [1, 1, 1, 1, executor.load_handle],
    "store": [1, 1, 1, 1, executor.store_handle],
    "txna": [1, 1, 1, 2, executor.txna_handle],
    "gtxna": [1, 1, 1, 3, executor.gtxna_handle],
    "gtxns": [1, 1, 1, 1, executor.gtxns_handle],
    "gtxnsa": [1, 1, 1, 2, executor.gtxnsa_handle],
    "gload": [1, 1, 0, 2, executor.gload_handle],
    "gloads": [1, 1, 0, 1, executor.gloads_handle],
    "gaid": [1, 1, 0, 1, executor.gaid_handle],
    "gaids": [1, 1, 0, 0, executor.gaids_handle],
    "bnz": [1, 1, 1, 1, executor.internel_jump],
    "bz": [1, 1, 1, 1, executor.internel_jump],
    "b": [1, 1, 1, 1, executor.internel_jump],
    "return": [1, 1, 1, 0, executor.return_handle],
    "assert": [1, 1, 1, 0, executor.assert_handle],
    "pop": [1, 1, 1, 0, executor.pop_handle],
    "dup": [1, 1, 1, 0, executor.dup_handle],
    "dup2": [1, 1, 1, 0, executor.dup2_handle],
    "dig": [1, 1, 1, 1, executor.dig_handle],
    "swap": [1, 1, 1, 0, executor.swap_handle],
    "cover": [1, 1, 1, 1, executor.cover_handle],
    "uncover": [1, 1, 1, 1, executor.uncover_handle],
    "concat": [1, 1, 1, 0, executor.concat_handle],
    "substring": [1, 1, 1, 2, executor.substring_handle],
    "substring3": [1, 1, 1, 0, executor.substring3_handle],
    "getbyte": [1, 1, 1, 0, executor.getbyte_handle],
    "extract": [1, 1, 1, 2, executor.extract_handle],
    "balance": [1, 1, 0, 0, executor.balance_handle],
    "app_opted_in": [1, 1, 0, 0, executor.app_opted_in_handle],
    "app_local_get": [1, 1, 0, 0, executor.app_local_get_handle],
    "app_global_get": [1, 1, 0, 0, executor.app_global_get_handle],
    "app_local_put": [1, 1, 0, 0, executor.app_local_put_handle],
    "app_global_put": [1, 1, 0, 0, executor.app_global_put_handle],
    "app_global_del": [1, 1, 0, 0, executor.app_global_del_handle],
    "asset_holding_get": [1, 1, 0, 1, executor.asset_holding_get_handle],
    "asset_params_get": [1, 1, 0, 1, executor.asset_params_get_handle],
    "app_params_get": [1, 1, 0, 1, executor.app_params_get_handle],
    "min_balance": [1, 1, 0, 0, executor.min_balance_handle],
    "pushbytes": [1, 1, 1, 1, executor.pushbytes_handle],
    "pushint": [1, 1, 1, 1, executor.pushint_handle],
    "callsub": [1, 1, 1, 1, executor.internel_jump],
    "retsub": [1, 1, 1, 0, executor.internel_jump],
    "shl": [1, 1, 1, 0, executor.shl_handle],
    "shr": [1, 1, 1, 0, executor.shr_handle],
    "sqrt": [4, 1, 1, 0, executor.sqrt_handle],
    "exp": [1, 1, 1, 0, executor.exp_handle],
    "bzero": [1, 1, 1, 0, executor.bzero_handle],
    "log": [1, 1, 0, 0, executor.log_handle],
    "itxn_begin": [1, 1, 0, 0, executor.itxn_begin_handle],
    "itxn_field": [1, 1, 0, 1, executor.itxn_field_handle],
    "itxn_submit": [1, 1, 0, 0, executor.itxn_submit_handle],
    "txnas": [1, 1, 1, 1, executor.txnas_handle],
    "gtxnas": [1, 1, 1, 2, executor.gtxnas_handle],
    "gtxnsas": [1, 1, 1, 1, executor.gtxnsas_handle],
    "args": [1, 0, 1, 0, executor.args_handle],
    "app_global_get_ex": [1, 1, 0, 0, executor.app_global_get_ex_handle],
    "app_local_get_ex": [1, 1, 0, 0, executor.app_local_get_ex_handle],
    "app_local_del": [1, 1, 0, 0, executor.app_local_del_handle],
    "extract3": [1, 1, 1, 0, executor.extract3_handle],
    "stores": [1, 1, 1, 0, executor.stores_handle],
    "loads": [1, 1, 1, 0, executor.loads_handle],
    "ed25519verify": [1900, 1, 1, 0, executor.ed25519verify_handle],
    "ecdsa_verify": [1700, 1, 1, 1, executor.ecdsa_verify_handle],
    "ecdsa_pk_decompress": [650, 1, 1, 1],
    "ecdsa_pk_recover": [2000, 1, 1, 1],
    "mulw": [1, 1, 1, 0],
    "addw": [1, 1, 1, 0],
    "divmodw": [20, 1, 1, 0],
    "extract_uint16": [1, 1, 1, 0],
    "extract_uint32": [1, 1, 1, 0],
    "extract_uint64": [1, 1, 1, 0],
    "setbyte": [1, 1, 1, 0],
    "getbit": [1, 1, 1, 0],
    "setbit": [1, 1, 1, 0],
    "select": [1, 1, 1, 0],
    "expw": [10, 1, 1, 0],
    "b+": [10, 1, 1, 0],
    "b-": [10, 1, 1, 0],
    "b/": [20, 1, 1, 0],
    "b*": [20, 1, 1, 0],
    "b<": [1, 1, 1, 0],
    "b>": [1, 1, 1, 0],
    "b<=": [1, 1, 1, 0],
    "b>=": [1, 1, 1, 0],
    "b==": [1, 1, 1, 0],
    "b!=": [1, 1, 1, 0],
    "b%": [20, 1, 1, 0],
    "b|": [6, 1, 1, 0],
    "b&": [6, 1, 1, 0],
    "b^": [6, 1, 1, 0],
    "b~": [4, 1, 1, 0],
    "bitlen": [1, 1, 1, 0],
    "itxn": [1, 1, 0, 1],
    "itxna": [1, 1, 0, 2],
}

CONSTANTS = {
    "NoOp": 0,
    "OptIn": 1,
    "CloseOut": 2,
    "ClearState": 3,
    "UpdateApplication": 4,
    "DeleteApplication": 5,
    "pay": 1,
    "keyreg": 2,
    "acfg": 3,
    "axfer": 4,
    "afrz": 5,
    "appl": 6,
}

def get_string_constant(key):
    if key in CONSTANTS:
        return str(CONSTANTS[key])
    else:
        return key

def get_cost(opcode):
    return OPCODES[opcode][COST]

def get_handle(opcode):
    try:
        return OPCODES[opcode][HANDLE]
    except:
        return None

def support_application_mode(opcode):
    return OPCODES[opcode][APPLICATION_MODE]

def support_signature_mode(opcode):
    return OPCODES[opcode][SIGNATURE_MODE]


def params_number(opcode):
    try:
        return OPCODES[opcode][PARAMS]
    except:
        log.error("Invalid opcode: {}".format(opcode))
        exit(runtime.INVALID_OPCODE)


