
# opcodes[name] has a list of [cost, whether support application mode, whether support signature mode,
# number of parameters, opcode handle function]
import runtime
import logging
import handler.debug
import handler.basis
import handler.v8
import handler.v7
import handler.v6
import handler.v5
import handler.v4
import handler.v3
import handler.v2
import handler.v1

log = logging.getLogger(__name__)

COST = 0
APPLICATION_MODE = 1
SIGNATURE_MODE = 2
PARAMS = 3
HANDLE = 4

# The tool supports all the opcodes for TEAL version 8
OPCODES = {
    # Debug handler
    "debug_display_global_state": [0, 1, 1, 0, handler.debug.debug_display_global_state], # Used for debugging
    "debug_display_stack": [0, 1, 1, 0, handler.debug.debug_display_stack], # Used for debugging
    "debug_exit": [0, 1, 1, 0, handler.debug.debug_exit], # Used for debugging
    
    # Basic handler
    "int": [1, 1, 1, 1, handler.basis.int_handle],
    "byte": [1, 1, 1, 1, handler.v3.pushbytes_handle],
    "addr": [1, 1, 1, 1, handler.basis.addr_handle],

    # TEAL version 1
    "intcblock": [1, 1, 1, -1, handler.v1.intcblock_handle],
    "bytecblock": [1, 1, 1, -1, handler.v1.bytecblock_handle],
    "sha256": [35, 1, 1, 0, handler.v1.sha256_handle],
    "keccak256": [130, 1, 1, 0, handler.v1.keccak256_handle],
    "sha512_256": [45, 1, 1, 0, handler.v1.sha512_256_handle],
    "+": [1, 1, 1, 0, handler.v1.add_handle],
    "-": [1, 1, 1, 0, handler.v1.sub_handle],
    "/": [1, 1, 1, 0, handler.v1.div_handle],
    "*": [1, 1, 1, 0, handler.v1.mul_handle],
    "<": [1, 1, 1, 0, handler.v1.LT_handle],
    ">": [1, 1, 1, 0, handler.v1.GT_handle],
    "<=": [1, 1, 1, 0, handler.v1.LE_handle],
    ">=": [1, 1, 1, 0, handler.v1.GE_handle],
    "&&": [1, 1, 1, 0, handler.v1.logic_and_handle],
    "||": [1, 1, 1, 0, handler.v1.logic_or_handle],
    "==": [1, 1, 1, 0, handler.v1.EQ_handle],
    "!=": [1, 1, 1, 0, handler.v1.NEQ_handle],
    "!": [1, 1, 1, 0, handler.v1.test_zero_handle],
    "len": [1, 1, 1, 0, handler.v1.len_handle],
    "itob": [1, 1, 1, 0, handler.v1.itob_handle],
    "btoi": [1, 1, 1, 0, handler.v1.btoi_handle],
    "%": [1, 1, 1, 0, handler.v1.rem_handle],
    "|": [1, 1, 1, 0, handler.v1.bit_or_handle],
    "&": [1, 1, 1, 0, handler.v1.bit_and_handle],
    "^": [1, 1, 1, 0, handler.v1.bit_xor_handle],
    "~": [1, 1, 1, 0, handler.v1.bit_not_handle],
    "intc": [1, 1, 1, 1, handler.v1.intc_handle],
    "intc_0": [1, 1, 1, 0, handler.v1.intc_0_handle],
    "intc_1": [1, 1, 1, 0, handler.v1.intc_1_handle],
    "intc_2": [1, 1, 1, 0, handler.v1.intc_2_handle],
    "intc_3": [1, 1, 1, 0, handler.v1.intc_3_handle],
    "bytec": [1, 1, 1, 1, handler.v1.bytec_handle],
    "bytec_0": [1, 1, 1, 0, handler.v1.bytec_0_handle],
    "bytec_1": [1, 1, 1, 0, handler.v1.bytec_1_handle],
    "bytec_2": [1, 1, 1, 0, handler.v1.bytec_2_handle],
    "bytec_3": [1, 1, 1, 0, handler.v1.bytec_3_handle],
    "arg": [1, 0, 1, 1, handler.v1.arg_handle],
    "arg_0": [1, 0, 1, 0, handler.v1.arg_i_handle],
    "arg_1": [1, 0, 1, 0, handler.v1.arg_i_handle],
    "arg_2": [1, 0, 1, 0, handler.v1.arg_i_handle],
    "arg_3": [1, 0, 1, 0, handler.v1.arg_i_handle],
    "txn": [1, 1, 1, 1, handler.v1.txn_handle],
    "global": [1, 1, 1, 1, handler.v1.global_handle],
    "gtxn": [1, 1, 1, 2, handler.v1.gtxn_handle],
    "load": [1, 1, 1, 1, handler.v1.load_handle],
    "store": [1, 1, 1, 1, handler.v1.store_handle],
    "pop": [1, 1, 1, 0, handler.v1.pop_handle],
    "dup": [1, 1, 1, 0, handler.v1.dup_handle],
    "ed25519verify": [1900, 1, 1, 0, handler.v1.ed25519verify_handle],
    "mulw": [1, 1, 1, 0, handler.v1.mulw_handle],
    "err": [1, 1, 1, 0, handler.v1.err_handle],
    "bnz": [1, 1, 1, 1, handler.basis.internel_jump],


    # TEAL version 2
    "txna": [1, 1, 1, 2, handler.v2.txna_handle],
    "gtxna": [1, 1, 1, 3, handler.v2.gtxna_handle],
    "return": [1, 1, 1, 0, handler.v2.return_handle],
    "dup2": [1, 1, 1, 0, handler.v2.dup2_handle],
    "concat": [1, 1, 1, 0, handler.v2.concat_handle],
    "substring": [1, 1, 1, 2, handler.v2.substring_handle],
    "substring3": [1, 1, 1, 0, handler.v2.substring3_handle],
    "balance": [1, 1, 0, 0, handler.v2.balance_handle],
    "app_opted_in": [1, 1, 0, 0, handler.v2.app_opted_in_handle],
    "app_local_get": [1, 1, 0, 0, handler.v2.app_local_get_handle],
    "app_global_get": [1, 1, 0, 0, handler.v2.app_global_get_handle],
    "app_local_put": [1, 1, 0, 0, handler.v2.app_local_put_handle],
    "app_global_put": [1, 1, 0, 0, handler.v2.app_global_put_handle],
    "app_global_del": [1, 1, 0, 0, handler.v2.app_global_del_handle],
    "asset_holding_get": [1, 1, 0, 1, handler.v2.asset_holding_get_handle],
    "asset_params_get": [1, 1, 0, 1, handler.v2.asset_params_get_handle],
    "app_global_get_ex": [1, 1, 0, 0, handler.v2.app_global_get_ex_handle],
    "app_local_get_ex": [1, 1, 0, 0, handler.v2.app_local_get_ex_handle],
    "app_local_del": [1, 1, 0, 0, handler.v2.app_local_del_handle],
    "addw": [1, 1, 1, 0, handler.v2.addw_handle],
    "bz": [1, 1, 1, 1, handler.basis.internel_jump],
    "b": [1, 1, 1, 1, handler.basis.internel_jump],

    # TEAL version 3
    "gtxns": [1, 1, 1, 1, handler.v3.gtxns_handle],
    "gtxnsa": [1, 1, 1, 2, handler.v3.gtxnsa_handle],
    "assert": [1, 1, 1, 0, handler.v3.assert_handle],
    "dig": [1, 1, 1, 1, handler.v3.dig_handle],
    "swap": [1, 1, 1, 0, handler.v3.swap_handle],
    "getbyte": [1, 1, 1, 0, handler.v3.getbyte_handle],
    "min_balance": [1, 1, 0, 0, handler.v3.min_balance_handle],
    "pushbytes": [1, 1, 1, 1, handler.v3.pushbytes_handle],
    "pushint": [1, 1, 1, 1, handler.v3.pushint_handle],
    "setbyte": [1, 1, 1, 0, handler.v3.setbyte_handle],
    "getbit": [1, 1, 1, 0, handler.v3.getbit_handle],
    "setbit": [1, 1, 1, 0, handler.v3.setbit_handle],
    "select": [1, 1, 1, 0, handler.v3.select_handle],

    # TEAL version 4
    "gload": [1, 1, 0, 2, handler.v4.gload_handle],
    "gloads": [1, 1, 0, 1, handler.v4.gloads_handle],
    "gaid": [1, 1, 0, 1, handler.v4.gaid_handle],
    "gaids": [1, 1, 0, 0, handler.v4.gaids_handle],
    "shl": [1, 1, 1, 0, handler.v4.shl_handle],
    "shr": [1, 1, 1, 0, handler.v4.shr_handle],
    "sqrt": [4, 1, 1, 0, handler.v4.sqrt_handle],
    "exp": [1, 1, 1, 0, handler.v4.exp_handle],
    "bzero": [1, 1, 1, 0, handler.v4.bzero_handle],
    "divmodw": [20, 1, 1, 0, handler.v4.divmodw_handle],
    "expw": [10, 1, 1, 0, handler.v4.expw_handle],
    "bitlen": [1, 1, 1, 0, handler.v4.bitlen_handle],
    "b+": [10, 1, 1, 0, handler.v4.Badd_handle],
    "b-": [10, 1, 1, 0, handler.v4.Bsub_handle],
    "b/": [20, 1, 1, 0, handler.v4.Bdiv_handle],
    "b*": [20, 1, 1, 0, handler.v4.Bmul_handle],
    "b<": [1, 1, 1, 0, handler.v4.BLT_handle],
    "b>": [1, 1, 1, 0, handler.v4.BGT_handle],
    "b<=": [1, 1, 1, 0, handler.v4.BLE_handle],
    "b>=": [1, 1, 1, 0, handler.v4.BGE_handle],
    "b==": [1, 1, 1, 0, handler.v4.BEQ_handle],
    "b!=": [1, 1, 1, 0, handler.v4.BNEQ_handle],
    "b%": [20, 1, 1, 0, handler.v4.Brem_handle],
    "b|": [6, 1, 1, 0, handler.v4.Bbit_or_handle],
    "b&": [6, 1, 1, 0, handler.v4.Bbit_and_handle],
    "b^": [6, 1, 1, 0, handler.v4.Bbit_xor_handle],
    "b~": [4, 1, 1, 0, handler.v4.Bbit_not_handle],
    "callsub": [1, 1, 1, 1, handler.basis.internel_jump],
    "retsub": [1, 1, 1, 0, handler.basis.internel_jump],

    # TEAL version 5
    "extract": [1, 1, 1, 2, handler.v5.extract_handle],
    "cover": [1, 1, 1, 1, handler.v5.cover_handle],
    "uncover": [1, 1, 1, 1, handler.v5.uncover_handle],
    "app_params_get": [1, 1, 0, 1, handler.v5.app_params_get_handle],
    "log": [1, 1, 0, 0, handler.v5.log_handle],
    "itxn_begin": [1, 1, 0, 0, handler.v5.itxn_begin_handle],
    "itxn_field": [1, 1, 0, 1, handler.v5.itxn_field_handle],
    "itxn_submit": [1, 1, 0, 0, handler.v5.itxn_submit_handle],
    "txnas": [1, 1, 1, 1, handler.v5.txnas_handle],
    "gtxnas": [1, 1, 1, 2, handler.v5.gtxnas_handle],
    "gtxnsas": [1, 1, 1, 1, handler.v5.gtxnsas_handle],
    "args": [1, 0, 1, 0, handler.v5.args_handle],
    "extract3": [1, 1, 1, 0, handler.v5.extract3_handle],
    "stores": [1, 1, 1, 0, handler.v5.stores_handle],
    "loads": [1, 1, 1, 0, handler.v5.loads_handle],
    "ecdsa_verify": [1700, 1, 1, 1, handler.v5.ecdsa_verify_handle],
    "ecdsa_pk_decompress": [650, 1, 1, 1, handler.v5.ecdsa_pk_decompress_handle],
    "ecdsa_pk_recover": [2000, 1, 1, 1, handler.v5.ecdsa_pk_recover_handle],
    "extract_uint16": [1, 1, 1, 0, handler.v5.extract_uint16_handle],
    "extract_uint32": [1, 1, 1, 0, handler.v5.extract_uint32_handle],
    "extract_uint64": [1, 1, 1, 0, handler.v5.extract_uint64_handle],
    "itxn": [1, 1, 0, 1, handler.v5.itxn_handle],
    "itxna": [1, 1, 0, 2, handler.v5.itxna_handle],

    # TEAL version 6
    "acct_params_get": [1, 1, 0, 1, handler.v6.acct_params_get_handle],
    "bsqrt": [40, 1, 1, 0, handler.v6.bsqrt_handle],
    "divw": [1, 1, 1, 0, handler.v6.divw_handle],
    "itxn_next": [1, 1, 0, 0, handler.v6.itxn_next_handle],
    "gitxn": [1, 1, 0, 2, handler.v6.gitxn_handle],
    "gitxna": [1, 1, 0, 3, handler.v6.gitxna_handle],
    "gloadss": [1, 1, 0, 0, handler.v6.gloadss_handle],
    "itxnas": [1, 1, 0, 1, handler.v6.itxnas_handle],
    "gitxnas": [1, 1, 0, 2, handler.v6.gitxnas_handle],

    # TEAL version 7
    "replace2": [1, 1, 1, 1, handler.v7.replace2_handle],
    "replace3": [1, 1, 1, 0, handler.v7.replace3_handle],
    "base64_decode": [2, 1, 1, 1, handler.v7.base64_decode_handle],
    "json_ref": [27, 1, 1, 1, handler.v7.json_ref_handle],
    "ed25519verify_bare": [1900, 1, 1, 0, handler.v7.ed25519verify_bare_handle],
    "sha3_256": [130, 1, 1, 0, handler.v7.sha3_256_handle],
    "vrf_verify": [5700, 1, 1, 1, handler.v7.vrf_verify_handle],
    "block": [1, 1, 1, 1, handler.v7.block_handle],

    # TEAL version 8
    "bury": [1, 1, 1, 1, handler.v8.bury_handle],
    "popn": [1, 1, 1, 1, handler.v8.popn_handle],
    "dupn": [1, 1, 1, 1, handler.v8.dupn_handle],
    "proto": [1, 1, 1, 2, handler.v8.proto_handle],
    "frame_dig": [1, 1, 1, 1, handler.v8.frame_dig_handle],
    "frame_bury": [1, 1, 1, 1, handler.v8.frame_bury_handle],
    "switch": [1, 1, 1, -1, handler.basis.internel_jump],

    "pushbytess": [1, 1, 1, -1],
    "pushints": [1, 1, 1, -1],
    "match": [1, 1, 1, -1],
    "box_create": [1, 1, 0, 0],
    "box_extract": [1, 1, 0, 0],
    "box_replace": [1, 1, 0, 0],
    "box_del": [1, 1, 0, 0],
    "box_len": [1, 1, 0, 0],
    "box_get": [1, 1, 0, 0],
    "box_put": [1, 1, 0, 0],
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


