import logging
import z3
import util
import runtime
import memory
import analyzer
import setting

log = logging.getLogger(__name__)

def dup2_handle(configuration, instruction):
    """
    Opcode: 0x4a
    Stack: ..., A, B -> ..., A, B, A, B
    duplicate A and B
    Availability: v2
    """
    # Note that the duplicate value is a reference of the original value
    val1 = configuration.stack_get(-2)
    val2 = configuration.stack_get(-1)
    configuration.stack_push(val1)
    configuration.stack_push(val2)
    return True


def concat_handle(configuration, instruction):
    """
    Opcode: 0x50
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    join A and B
    Availability: v2
    """
    val1 = configuration.stack_pop("bytes")
    val2 = configuration.stack_pop("bytes")
    result = val2 + val1

    runtime.solver.add( z3.Length(result) <= 4096 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid concat opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (concat_handle)")
        return False

    configuration.stack_push( util.Bytes(result) )
    return True


def app_global_put_handle(configuration, instruction):
    """
    Opcode: 0x67
    Stack: ..., A: []byte, B -> ...
    write B to key A in the global state of the current application
    Availability: v2
    Mode: Application
    """
    configuration.opcode_record["app_global_put"] = True
    val_dict1 = configuration.stack_pop("original")
    val2 = configuration.stack_pop("bytes")
    runtime.solver.add( z3.Length(val2) <= 64 )
    if val_dict1["type"] == "undefined":
        # If we do not know the variable type, simply put it to both array!
        uint_dict = util.deepcopy(val_dict1)
        bytes_dict = util.deepcopy(val_dict1)
        memory.Define( uint_dict, "uint", configuration )
        memory.Define( bytes_dict, "bytes", configuration )
        configuration.global_state_return_uint = z3.Store(configuration.global_state_return_uint, val2, uint_dict["value"])
        configuration.global_state_return_bytes = z3.Store(configuration.global_state_return_bytes, val2, bytes_dict["value"])
        log.debug("app_global_put_handle gets undefined variable")
    elif val_dict1["type"] == "uint":
        configuration.global_state_return_uint = z3.Store(configuration.global_state_return_uint, val2, val_dict1["value"])
    elif val_dict1["type"] == "bytes":
        runtime.solver.add( z3.Length(val2) + z3.Length(val_dict1["value"]) <= 128 )
        configuration.global_state_return_bytes = z3.Store(configuration.global_state_return_bytes, val2, val_dict1["value"])

    flag = runtime.solver.check()
    if flag == z3.sat:
        return True
    elif flag == z3.unsat:
        log.info("Invalid data format in app_global_put_handle")
        return False
    else:
        log.info("Z3 timeout (app_global_put_handle)")
        return False


def app_global_get_handle(configuration, instruction):
    """
    Opcode: 0x64
    Stack: ..., A: []byte -> ..., any
    global state of the key A in the current application
    Availability: v2
    Mode: Application
    """
    val1 = configuration.stack_pop("bytes")
    result_dict = util.Undefined({
        "array": "global_state",
        "op1": val1,
    })

    # Try to handle constant key directly
    memory.try_define(result_dict, configuration)
    configuration.stack_push(result_dict)
    return True


def return_handle(configuration, instruction):
    """
    Opcode: 0x43
    Stack: ..., A: uint64 -> ...
    use A as success value; end
    Availability: v2
    """
    runtime.total_path += 1
    val1 = configuration.stack_pop("uint")
    runtime.solver.add( val1 != 0 )
    flag = runtime.solver.check()
    if flag == z3.sat:
        runtime.feasible_path += 1
        analyzer.run(configuration)
    elif flag == z3.unknown:
        log.info("Z3 timeout (return_handle)")
    return False


def substring3_handle(configuration, instruction): 
    """
    Opcode: 0x52
    Stack: ..., A: []byte, B: uint64, C: uint64 -> ..., []byte
    A range of bytes from A starting at B up to but not including C.
    Availability: v2
    """
    end = configuration.stack_pop("uint")
    start = configuration.stack_pop("uint")
    str_val = configuration.stack_pop("bytes")
    length =  end - start
    runtime.solver.add( start <= end )
    runtime.solver.add( z3.BV2Int(end) <= z3.Length(str_val) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid substring3 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (substring3_handle)")
        return False


    result = z3.SubString(str_val, z3.BV2Int(start), z3.BV2Int(length))
    configuration.stack_push( util.Bytes(result))
    return True


def substring_handle(configuration, instruction): 
    """
    Opcode: 0x51 {uint8 start position} {uint8 end position}
    Stack: ..., A: []byte -> ..., []byte
    A range of bytes from A starting at S up to but not including E.
    Availability: v2
    """
    val1 = configuration.stack_pop("bytes")
    start = int(instruction["params"][0])
    end = int(instruction["params"][1])
    length =  end - start
    if start > end:
        log.info("Invalid substring opcode")
        return False
    runtime.solver.add( end <= z3.Length(val1) )

    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid substring opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (substring_handle)")
        return False

    result = z3.SubString(val1, start, length)
    configuration.stack_push( util.Bytes(result))
    return True


def txna_handle(configuration, instruction):
    """
    Opcode: 0x36 {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ... -> ..., any
    Ith value of the array field F of the current transaction
    Availability: v2
    """
    param0 = instruction["params"][0]
    param1 = z3.BitVecVal( int(instruction["params"][1]), 64 )
    index = runtime.get_group_index(configuration)

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, index, param1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, index, param1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, index, param1) )
    elif param0 == "Accounts":
        if int(instruction["params"][1]) == 0:
            if setting.IS_SMART_CONTRACT:
                # Arbitrary sender address is OK in smart contract
                dict_result = util.Bytes( z3.StringVal( setting.sender_address ) )
            else:
                dict_result = util.Bytes( z3.Select(memory.gtxn_Sender, index) )
        else:
            dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, index, param1) )
    elif param0 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, index, param1) )
    elif param0 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, index, param1) )
    elif param0 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, index, param1) )
    else:
        log.error("unrecognised opcode: <txna {} {}>".format(param0, param1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


def gtxna_handle(configuration, instruction):
    """
    Opcode: 0x37 {uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ... -> ..., any
    Ith value of the array field F from the Tth transaction in the current group
    Availability: v2
    """
    param0 = z3.BitVecVal( int(instruction["params"][0]), 64 )
    param1 = instruction["params"][1]
    param2 = z3.BitVecVal( int(instruction["params"][2]), 64 )

    if param1 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, param0, param2) )
    elif param1 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, param0, param2) )
    elif param1 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, param0, param2) )
    elif param1 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, param0, param2) )
    elif param1 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, param0, param2) )
    elif param1 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, param0, param2) )
    elif param1 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, param0, param2) )
    else:
        log.error("unrecognised opcode: <gtxna {} {} {}>".format(param0, param1, param2))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


def asset_holding_get_handle(configuration, instruction):
    """
    Opcode: 0x70 {uint8 asset holding field index}
    Stack: ..., A, B: uint64 -> ..., X: any, Y: uint64
    X is field F from account A's holding of asset B. Y is 1 if A is opted into B, else 0
    Availability: v2
    Mode: Application
    """
    param0 = instruction["params"][0]
    assetID = configuration.stack_pop("uint")
    account = configuration.stack_pop("original")

    if z3.is_bv_value(assetID):
        analyzer.check_asset(assetID.as_long())

    if account["type"] == "undefined":
        log.info("asset_holding_get_handle gets undefined variable")
        return False
    elif account["type"] == "uint":
        if param0 == "AssetBalance":
            result = memory.select_2D_array(memory.asset_holding_balance_uint, account["value"], assetID)
        elif param0 == "AssetFrozen":
            result = memory.select_2D_array(memory.asset_holding_frozen_uint, account["value"], assetID)
        else:
            log.error("unrecognised opcode: <asset_holding_get {}>".format(param0))
            exit(runtime.UNRECOGNISED_OPCODE)
    elif account["type"] == "bytes":
        if param0 == "AssetBalance":
            result = memory.select_2D_array(memory.asset_holding_balance_bytes, account["value"], assetID)
        elif param0 == "AssetFrozen":
            result = memory.select_2D_array(memory.asset_holding_frozen_bytes, account["value"], assetID)
        else:
            log.error("unrecognised opcode: <asset_holding_get {}>".format(param0))
            exit(runtime.UNRECOGNISED_OPCODE)    
    configuration.stack_push( util.Uint(result) )
    # Always opt-in
    configuration.stack_push( util.Uint( z3.BitVecVal(1, 64) ) )
    return True


def balance_handle(configuration, instruction):
    """
    Opcode: 0x60
    Stack: ..., A -> ..., uint64
    get balance for account A, in microalgos. 
    Availability: v2
    Mode: Application
    """
    val1 = configuration.stack_pop("original")
    if val1["type"] == "undefined":
        log.info("balance_handle gets undefined variable")
        return False
    elif val1["type"] == "uint":
        result = z3.Select(memory.balance_array_uint, val1["value"])
    elif val1["type"] == "bytes":
        result = z3.Select(memory.balance_array_bytes, val1["value"])
    runtime.solver.add(result >= 100000)
    configuration.stack_push( util.Uint(result) )
    return True


def app_local_get_handle(configuration, instruction):
    """
    Opcode: 0x62
    Stack: ..., A, B: []byte -> ..., any
    local state of the key B in the current application in account A
    Availability: v2
    Mode: Application
    """
    configuration.opcode_record["app_local_get"] = True
    key = configuration.stack_pop("bytes")
    account = configuration.stack_pop("original")
    if account["type"] == "undefined":
        log.info("app_local_get_handle gets undefined variable")
        return False
    result_dict = util.Undefined({
        "array": "local_state",
        "op1": account["value"],
        "op1_type": account["type"],
        "op2": key,
    })
    configuration.opcode_record["local_users"].append(str(account["value"]))
    configuration.stack_push(result_dict)
    return True


def app_global_get_ex_handle(configuration, instruction):
    """
    Opcode: 0x65
    Stack: ..., A: uint64, B: []byte -> ..., X: any, Y: uint64
    X is the global state of application A, key B. Y is 1 if key existed, else 0
    Availability: v2
    Mode: Application
    """
    key = configuration.stack_pop("bytes")
    appID = configuration.stack_pop("uint")
    value_dict = util.Undefined({
        "array": "global_state_ex",
        "op1": appID,
        "op2": key,
    })

    configuration.stack_push(value_dict)
    # Assume that the global state key always exists
    configuration.stack_push( util.Uint( z3.BitVecVal(1, 64) ) )
    return True


def app_local_get_ex_handle(configuration, instruction):
    """
    Opcode: 0x63
    Stack: ..., A, B: uint64, C: []byte -> ..., X: any, Y: uint64
    X is the local state of application B, key C in account A. Y is 1 if key existed, else 0
    Availability: v2
    Mode: Application
    """
    key = configuration.stack_pop("bytes")
    appID = configuration.stack_pop("uint")
    account = configuration.stack_pop("original")
    if account["type"] == "undefined":
        log.info("app_local_get_ex_handle gets undefined variable")
        return False

    value_dict = util.Undefined({
        "array": "local_state_ex",
        "op1": appID,
        "op2": account["value"],
        "op2_type": account["type"],
        "op3": key,
    })

    configuration.stack_push(value_dict)
    # Assume that the global state key always exists
    configuration.stack_push( util.Uint( z3.BitVecVal(1, 64) ) )
    return True


def app_local_put_handle(configuration, instruction):
    """
    Opcode: 0x66
    Stack: ..., A, B: []byte, C -> ...
    write C to key B in account A's local state of the current application
    Availability: v2
    Mode: Application
    """
    content = configuration.stack_pop("original")
    key = configuration.stack_pop("bytes")
    account = configuration.stack_pop("original")

    configuration.opcode_record["app_local_put"] = True
    configuration.opcode_record["local_users"].append(str(account["value"]))

    runtime.solver.add( z3.Length(key) <= 64 )
    
    if account["type"] == "undefined":
        log.info("app_local_put_handle gets undefined variable")
        return False
    elif content["type"] == "undefined":
        uint_dict = util.deepcopy(content)
        bytes_dict = util.deepcopy(content)
        memory.Define( uint_dict, "uint", configuration )
        memory.Define( bytes_dict, "bytes", configuration )
        if account["type"] == "uint":
            configuration.local_state_uint_return_uint = memory.store_2D_array(
                configuration.local_state_uint_return_uint, account["value"], key, uint_dict["value"])
            configuration.local_state_uint_return_bytes = memory.store_2D_array(
                configuration.local_state_uint_return_bytes, account["value"], key, bytes_dict["value"])
        elif account["type"] == "bytes":
            configuration.local_state_bytes_return_uint = memory.store_2D_array(
                configuration.local_state_bytes_return_uint, account["value"], key, uint_dict["value"])
            configuration.local_state_bytes_return_bytes = memory.store_2D_array(
                configuration.local_state_bytes_return_bytes, account["value"], key, bytes_dict["value"])
    elif content["type"] == "uint":
        if account["type"] == "uint":
            runtime.solver.add( account["value"] <= 4 )
            configuration.local_state_uint_return_uint = memory.store_2D_array(
                configuration.local_state_uint_return_uint, account["value"], key, content["value"])
        elif account["type"] == "bytes":
            runtime.solver.add( z3.Length(account["value"]) == 32 )
            configuration.local_state_bytes_return_uint = memory.store_2D_array(
                configuration.local_state_bytes_return_uint, account["value"], key, content["value"])
    elif content["type"] == "bytes":
        runtime.solver.add( z3.Length(key) + z3.Length(content["value"]) <= 128 )
        if account["type"] == "uint":
            runtime.solver.add( account["value"] <= 4 )
            configuration.local_state_uint_return_bytes = memory.store_2D_array(
                configuration.local_state_uint_return_bytes, account["value"], key, content["value"])
        elif account["type"] == "bytes":
            runtime.solver.add( z3.Length(account["value"]) == 32 )
            configuration.local_state_bytes_return_bytes = memory.store_2D_array(
                configuration.local_state_bytes_return_bytes, account["value"], key, content["value"])
    
    flag = runtime.solver.check()
    if flag == z3.sat:
        return True
    elif flag == z3.unsat:
        log.info("Invalid data format in app_local_put_handle")
        return False
    else:
        log.info("Z3 timeout (app_local_put_handle)")
        return False


def asset_params_get_handle(configuration, instruction):
    """
    Opcode: 0x71 {uint8 asset params field index}
    Stack: ..., A: uint64 -> ..., X: any, Y: uint64
    X is field F from asset A. Y is 1 if A exists, else 0
    Availability: v2
    Mode: Application
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("uint")

    if z3.is_bv_value(val1):
        analyzer.check_asset(val1.as_long())

    if param0 == "AssetTotal":
        dict_result = util.Uint( z3.Select(memory.AssetTotal, val1) )
    elif param0 == "AssetDecimals":
        dict_result = util.Uint( z3.Select(memory.AssetDecimals, val1) )
    elif param0 == "AssetDefaultFrozen":
        dict_result = util.Uint( z3.Select(memory.AssetDefaultFrozen, val1) )
    elif param0 == "AssetUnitName":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetUnitName, val1)) <= 8)
        dict_result = util.Bytes( z3.Select(memory.AssetUnitName, val1) )
    elif param0 == "AssetName":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetName, val1)) <= 32)
        dict_result = util.Bytes( z3.Select(memory.AssetName, val1) )
    elif param0 == "AssetURL":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetURL, val1)) <= 96)
        dict_result = util.Bytes( z3.Select(memory.AssetURL, val1) )
    elif param0 == "AssetMetadataHash":
        dict_result = util.Bytes( z3.Select(memory.AssetMetadataHash, val1) )
    elif param0 == "AssetManager":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetManager, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.AssetManager, val1) )
    elif param0 == "AssetReserve":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetReserve, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.AssetReserve, val1) )
    elif param0 == "AssetFreeze":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetFreeze, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.AssetFreeze, val1) )
    elif param0 == "AssetClawback":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetClawback, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.AssetClawback, val1) )
    elif param0 == "AssetCreator":
        runtime.solver.add(z3.Length(z3.Select(memory.AssetCreator, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.AssetCreator, val1) )
    configuration.stack_push(dict_result)
    configuration.stack_push(util.Uint( z3.BitVecVal( 1, 64 ))) # Always exist
    return True


def app_opted_in_handle(configuration, instruction):
    """
    Opcode: 0x61
    Stack: ..., A, B: uint64 -> ..., uint64
    1 if account A is opted in to application B, else 0
    Availability: v2
    Mode: Application
    """
    configuration.stack_pop("uint")
    configuration.stack_pop("original")
    result = z3.BitVecVal( 1, 64 )
    configuration.stack_push( util.Uint(result) )
    return True


def app_global_del_handle(configuration, instruction):
    """
    Opcode: 0x69
    Stack: ..., A: []byte -> ...
    delete key A from the global state of the current application
    Availability: v2
    Mode: Application
    """
    val1 = configuration.stack_pop("bytes")
    configuration.global_state_return_uint = z3.Store(configuration.global_state_return_uint, val1, z3.BitVecVal(0,64))
    configuration.global_state_return_bytes = z3.Store(configuration.global_state_return_bytes, val1, z3.StringVal(""))
    return True


def app_local_del_handle(configuration, instruction):
    """
    Opcode: 0x68
    Stack: ..., A, B: []byte -> ...
    delete key B from account A's local state of the current application
    Availability: v2
    Mode: Application
    """
    key = configuration.stack_pop("bytes")
    account = configuration.stack_pop("original")
    if account["type"] == "undefined":
        log.info("app_local_del_handle gets undefined variable")
        return False
    elif account["type"] == "uint":
        configuration.local_state_uint_return_uint = memory.store_2D_array(configuration.local_state_uint_return_uint, account["value"], key, z3.BitVecVal(0,64))
        configuration.local_state_uint_return_bytes = memory.store_2D_array(configuration.local_state_uint_return_bytes, account["value"], key, z3.StringVal(""))
    elif account["type"] == "bytes":
        configuration.local_state_bytes_return_uint = memory.store_2D_array(configuration.local_state_bytes_return_uint, account["value"], key, z3.BitVecVal(0,64))
        configuration.local_state_bytes_return_bytes = memory.store_2D_array(configuration.local_state_bytes_return_bytes, account["value"], key, z3.StringVal(""))
    return True


# This implementation is deprecated because z3.BV2Int() is inefficient
def addw_handle_deprecated(configuration, instruction):
    """
    Opcode: 0x1e
    Stack: ..., A: uint64, B: uint64 -> ..., X: uint64, Y: uint64
    A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.
    Availability: v2
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    result = z3.Int2BV(z3.BV2Int(valA) + z3.BV2Int(valB), 128)
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True


def addw_handle(configuration, instruction):
    """
    Opcode: 0x1e
    Stack: ..., A: uint64, B: uint64 -> ..., X: uint64, Y: uint64
    A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.
    Availability: v2
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    valB = z3.Concat(z3.BitVecVal(0, 64), valB)
    valA = z3.Concat(z3.BitVecVal(0, 64), valA)
    
    result = valA + valB    
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True