import logging
import z3
import util
import runtime
import memory
import random

log = logging.getLogger(__name__)


def itxna_handle(configuration, instruction):
    """
    Opcode: 0xb5 {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ... -> ..., any
    Ith value of the array field F of the last inner transaction
    Availability: v5
    Mode: Application
    """

    param0 = instruction["params"][0]
    param1 = int(instruction["params"][1])

    if param0 in ["ApplicationArgs", "Accounts", "Assets", "Applications", "Logs", "ApprovalProgramPages", "ClearStateProgramPages"]:
        log.info("Invalid itxna opcode")
        return False
    
    try:
        configuration.stack_push( runtime.itxn_field[runtime.itxn_index][param0][param1] )
    except:
        log.info("Invalid itxna opcode")
        return False
    
    return True

def itxn_handle(configuration, instruction):
    """
    Opcode: 0xb4 {uint8 transaction field index}
    Stack: ... -> ..., any
    field F of the last inner transaction
    Availability: v5
    Mode: Application
    """

    param0 = instruction["params"][0]
    if param0 not in runtime.itxn_field[runtime.itxn_index]:
        if param0 in ["CreatedAssetID", "CreatedApplicationID"]:
            runtime.itxn_field[runtime.itxn_index][param0] = util.Uint( z3.BitVecVal(int(random.random()*1000000000), 64) )
        else:
            log.info("Unsupport field in itxn opcode")
            return False

    configuration.stack_push( runtime.itxn_field[runtime.itxn_index][param0] )
    return True

def loads_handle(configuration, instruction):
    """
    Opcode: 0x3e
    Stack: ..., A: uint64 -> ..., any
    Ath scratch space value. All scratch spaces are 0 at program start.
    Availability: v5
    """
    val1 = configuration.stack_pop("uint")
    runtime.solver.add( val1 < 256 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.error("Invalid scratch index")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (loads_handle)")
        return False
    
    result_dict = util.Undefined({
        "array": "scratch_space",
        "op1": val1,
    })
    configuration.stack_push(result_dict)
    return True

def stores_handle(configuration, instruction):
    """
    Opcode: 0x3f
    Stack: ..., A: uint64, B -> ...
    store B to the Ath scratch space
    Availability: v5
    """
    
    val_dict1 = configuration.stack_pop("original")
    val2 = configuration.stack_pop("uint")

    runtime.solver.add( val2 < 256 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.error("Invalid scratch index")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (stores_handle)")
        return False

    if val_dict1["type"] == "undefined":
        # If we do not know the variable type, simply put it to both array!
        uint_dict = util.deepcopy(val_dict1)
        bytes_dict = util.deepcopy(val_dict1)
        memory.Define( uint_dict, "uint", configuration )
        memory.Define( bytes_dict, "bytes", configuration )
        configuration.scratch_space_return_uint = z3.Store(configuration.scratch_space_return_uint, val2, uint_dict["value"])
        configuration.scratch_space_return_bytes = z3.Store(configuration.scratch_space_return_bytes, val2, bytes_dict["value"])
        log.debug("stores_handle gets undefined variable")
    elif val_dict1["type"] == "uint":
        configuration.scratch_space_return_uint = z3.Store(configuration.scratch_space_return_uint, val2, val_dict1["value"])
    elif val_dict1["type"] == "bytes":
        configuration.scratch_space_return_bytes = z3.Store(configuration.scratch_space_return_bytes, val2, val_dict1["value"])
    return True

def cover_handle(configuration, instruction):
    """
    Opcode: 0x4e {uint8 depth}
    Stack: ..., [N items], A -> ..., A, [N items]
    remove top of stack, and place it deeper in the stack such that N elements are above it. Fails if stack depth <= N.
    Availability: v5
    """
    param0 = int(instruction["params"][0])
    if param0 == 0:
        log.info("Invalid cover parameter")
        return False
    elif param0 > len(configuration.stack):
        log.info("invalid stack operation in 'cover' opcode")
        return False
    val_dict1 = configuration.stack_pop("original")
    configuration.stack.insert(-param0, val_dict1)
    return True

def uncover_handle(configuration, instruction):
    """
    Opcode: 0x4f {uint8 depth}
    Stack: ..., A, [N items] -> ..., [N items], A
    remove the value at depth N in the stack and shift above items down so the Nth deep value is on top of the stack. Fails if stack depth <= N.
    Availability: v5
    """
    param0 = int(instruction["params"][0])
    if param0 >= len(configuration.stack):
        log.info("invalid stack operation in 'uncover' opcode")
        return False
    val_dict1 = configuration.stack.pop(-param0-1)
    configuration.stack_push(val_dict1)
    return True


def ecdsa_verify_handle(configuration, instruction):
    """
    Opcode: 0x05 {uint8 curve index}
    Stack: ..., A: []byte, B: []byte, C: []byte, D: []byte, E: []byte -> ..., uint64
    for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}
    Availability: v5
    """
    configuration.symbolic_hash_variable_used = True
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    
    # Always True
    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    log.info("Function ecdsa_verify detected")
    return True

def txnas_handle(configuration, instruction):
    """
    Opcode: 0xc0 {uint8 transaction field index}
    Stack: ..., A: uint64 -> ..., any
    Ath value of the array field F of the current transaction
    Availability: v5
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("uint")
    index = runtime.get_group_index(configuration)

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, index, val1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, index, val1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, index, val1) )
    elif param0 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, index, val1) )
    elif param0 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, index, val1) )
    elif param0 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, index, val1) )
    elif param0 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, index, val1) )
    else:
        log.error("unrecognised opcode: <txnas {} {}>".format(param0, val1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True

def gtxnas_handle(configuration, instruction):
    """
    Opcode: 0xc1 {uint8 transaction group index} {uint8 transaction field index}
    Stack: ..., A: uint64 -> ..., any
    Ath value of the array field F from the Tth transaction in the current group
    Availability: v5
    """
    param0 = z3.BitVecVal( int(instruction["params"][0]), 64 )
    param1 = instruction["params"][1]
    val1 = configuration.stack_pop("uint")

    if param1 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, param0, val1) )
    elif param1 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, param0, val1) )
    elif param1 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, param0, val1) )
    elif param1 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, param0, val1) )
    elif param1 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, param0, val1) )
    elif param1 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, param0, val1) )
    elif param1 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, param0, val1) )
    else:
        log.error("unrecognised opcode: <gtxnas {} {} {}>".format(param0, param1, val1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True

def gtxnsas_handle(configuration, instruction):
    """
    Opcode: 0xc2 {uint8 transaction field index}
    Stack: ..., A: uint64, B: uint64 -> ..., any
    Bth value of the array field F from the Ath transaction in the current group
    Availability: v5
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, val2, val1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, val2, val1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, val2, val1) )
    elif param0 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, val2, val1) )
    elif param0 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, val2, val1) )
    elif param0 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, val2, val1) )
    elif param0 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, val2, val1) )
    else:
        log.error("unrecognised opcode: <gtxnsas {} {} {}>".format(val2, param0, val1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True

def log_handle(configuration, instruction):
    """
    Opcode: 0xb0
    Stack: ..., A: []byte -> ...
    write A to log state of the current application
    Availability: v5
    Mode: Application
    """
    configuration.stack_pop("bytes")
    return True

def itxn_begin_handle(configuration, instruction):
    """
    Opcode: 0xb1
    Stack: ... -> ...
    begin preparation of a new inner transaction in a new transaction group
    Availability: v5
    Mode: Application
    """
    runtime.itxn_field = {}
    runtime.itxn_index = 0
    for i in range(16):
        runtime.itxn_field[i] = {
            "ApplicationArgs": [],
            "Accounts": [],
            "Assets": [],
            "Applications": [],
            "Logs": [],
            "ApprovalProgramPages": [],
            "ClearStateProgramPages": [],
        }
    return True


def itxn_field_handle(configuration, instruction):
    """
    Opcode: 0xb2 {uint8 transaction field index}
    Stack: ..., A -> ...
    set field F of the current inner transaction to A
    Availability: v5
    Mode: Application
    """

    val = configuration.stack_pop("original")
    param0 = instruction["params"][0]

    if param0 == "Fee":
        if (val["type"] == "uint" and (not z3.is_bv_value(val["value"]))) or val["type"] == "undefined":
            configuration.symbolic_inner_txn_fee = True

    if param0 in ["ApplicationArgs", "Accounts", "Assets", "Applications", "Logs", "ApprovalProgramPages", "ClearStateProgramPages"]:
        runtime.itxn_field[runtime.itxn_index][param0].append(val)
    else:
        runtime.itxn_field[runtime.itxn_index][param0] = val

    return True


def itxn_submit_handle(configuration, instruction):
    """
    Opcode: 0xb3
    Stack: ... -> ...
    execute the current inner transaction group. 
    Availability: v5
    Mode: Application
    """
    configuration.opcode_record["itxn_submit"] = True
    return True

def app_params_get_handle(configuration, instruction):
    """
    Opcode: 0x72 {uint8 app params field index}
    Stack: ..., A: uint64 -> ..., X: any, Y: uint64
    X is field F from app A. Y is 1 if A exists, else 0
    Availability: v5
    Mode: Application
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("uint")

    if param0 == "AppGlobalNumUint":
        dict_result = util.Uint( z3.Select(memory.AppGlobalNumUint_uint, val1) )
    elif param0 == "AppGlobalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.AppGlobalNumByteSlice_uint, val1) )
    elif param0 == "AppLocalNumUint":
        dict_result = util.Uint( z3.Select(memory.AppLocalNumUint_uint, val1) )
    elif param0 == "AppLocalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.AppLocalNumByteSlice_uint, val1) )
    elif param0 == "AppExtraProgramPages":
        runtime.solver.add(z3.Select(memory.AppExtraProgramPages_uint, val1) <= 3)
        dict_result = util.Uint( z3.Select(memory.AppExtraProgramPages_uint, val1) )
    elif param0 == "AppApprovalProgram":
        dict_result = util.Bytes( z3.Select(memory.AppApprovalProgram_uint, val1) )
    elif param0 == "AppClearStateProgram":
        dict_result = util.Bytes( z3.Select(memory.AppClearStateProgram_uint, val1) )
    elif param0 == "AppCreator":
        dict_result = util.Bytes( z3.StringVal( "\x01" * 32 ) )
    elif param0 == "AppAddress":
        dict_result = util.Bytes( z3.Select(memory.AppAddress_uint, val1) )

    configuration.stack_push(dict_result)
    configuration.stack_push(util.Uint( z3.BitVecVal( 1, 64 ))) # Always exist
    return True

def extract_handle(configuration, instruction):
    """
    Opcode: 0x57 {uint8 start position} {uint8 length}
    Stack: ..., A: []byte -> ..., []byte
    A range of bytes from A starting at S up to but not including S+L. 
    Availability: v5
    """
    start = int(instruction["params"][0])
    length = int(instruction["params"][1])
    string = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(string) >= start + length )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid extract opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (extract_handle)")
        return False

    result = z3.SubString(string, start, length)
    configuration.stack_push( util.Bytes(result) )
    return True


def extract3_handle(configuration, instruction):
    """
    Opcode: 0x58
    Stack: ..., A: []byte, B: uint64, C: uint64 -> ..., []byte
    A range of bytes from A starting at B up to but not including B+C.
    Availability: v5
    """
    length = configuration.stack_pop("uint")
    start = configuration.stack_pop("uint")
    string = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(string) >= z3.BV2Int(start) + z3.BV2Int(length) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid extract3 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (extract3_handle)")
        return False
    
    result = z3.SubString(string, z3.BV2Int(start), z3.BV2Int(length))
    configuration.stack_push( util.Bytes(result) )
    return True


def args_handle(configuration, instruction):
    """
    Opcode: 0xc3
    Stack: ..., A: uint64 -> ..., []byte
    Ath LogicSig argument
    Availability: v5
    Mode: Signature
    """
    val1 = configuration.stack_pop("uint")    
    result = z3.Select(memory.args, val1)
    configuration.stack_push( util.Bytes(result) )
    return True


def ecdsa_pk_decompress_handle(configuration, instruction):
    """
    Opcode: 0x06 {uint8 curve index}
    Stack: ..., A: []byte -> ..., X: []byte, Y: []byte
    decompress pubkey A into components X, Y
    Availability: v5
    """    
    configuration.symbolic_hash_variable_used = True
    val1 = configuration.stack_pop("bytes")
    resultX = z3.String( "ecdsa_pk_decompress({}_X)".format(val1.__str__()) )
    resultY = z3.String( "ecdsa_pk_decompress({}_Y)".format(val1.__str__()) )

    runtime.solver.add( z3.Length(val1) == 33 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("The input of ecdsa_pk_decompress is not 33 bytes long")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (ecdsa_pk_decompress_handle)")
        return False


    configuration.stack_push( util.Bytes(resultX) )
    configuration.stack_push( util.Bytes(resultY) )
    log.info("Function ecdsa_pk_decompress detected")
    return True


def ecdsa_pk_recover_handle(configuration, instruction):
    """
    Opcode: 0x07 {uint8 curve index}
    Stack: ..., A: []byte, B: uint64, C: []byte, D: []byte -> ..., X: []byte, Y: []byte
    for (data A, recovery id B, signature C, D) recover a public key
    Cost: 2000
    Availability: v5
    """    
    configuration.symbolic_hash_variable_used = True
    valD = configuration.stack_pop("bytes")
    valC = configuration.stack_pop("bytes")
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")

    pkID = valA.__str__() + valB.__str__() + valC.__str__() + valD.__str__()

    resultX = z3.String( "ecdsa_pk_recover({}_X)".format(pkID) )
    resultY = z3.String( "ecdsa_pk_recover({}_Y)".format(pkID) )

    configuration.stack_push( util.Bytes(resultX) )
    configuration.stack_push( util.Bytes(resultY) )
    log.info("Function ecdsa_pk_recover detected")
    return True


def extract_uint16_handle(configuration, instruction):
    """
    Opcode: 0x59
    Stack: ..., A: []byte, B: uint64 -> ..., uint64
    A uint16 formed from a range of big-endian bytes from A starting at B up to but not including B+2. If B+2 is larger than the array length, the program fails
    Availability: v5
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(valA) > z3.BV2Int(valB) + 1)

    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid extract_uint16 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (extract_uint16)")
        return False

    result_string = z3.SubString(valA, z3.BV2Int(valB), 2)
   
    result1 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 0, 1)) ,8)
    result2 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 1, 1)) ,8)

    final_result = z3.Concat(z3.BitVecVal(0, 48), result1, result2)

    configuration.stack_push( util.Uint(final_result) )
    return True

def extract_uint32_handle(configuration, instruction):
    """
    Opcode: 0x5a
    Stack: ..., A: []byte, B: uint64 -> ..., uint64
    A uint32 formed from a range of big-endian bytes from A starting at B up to but not including B+4. If B+4 is larger than the array length, the program fails
    Availability: v5
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(valA) > z3.BV2Int(valB) + 3)

    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid extract_uint32 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (extract_uint32)")
        return False
    
    result_string = z3.SubString(valA, z3.BV2Int(valB), 4)
   
    result1 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 0, 1)) ,8)
    result2 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 1, 1)) ,8)
    result3 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 2, 1)) ,8)
    result4 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 3, 1)) ,8)

    final_result = z3.Concat(z3.BitVecVal(0, 32), result1, result2, result3, result4)

    configuration.stack_push( util.Uint(final_result) )
    return True



def extract_uint64_handle(configuration, instruction):
    """
    Opcode: 0x5b
    Stack: ..., A: []byte, B: uint64 -> ..., uint64
    A uint64 formed from a range of big-endian bytes from A starting at B up to but not including B+8. If B+8 is larger than the array length, the program fails
    Availability: v5
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(valA) > z3.BV2Int(valB) + 7)

    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid extract_uint64 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (extract_uint64)")
        return False
    
    result_string = z3.SubString(valA, z3.BV2Int(valB), 8)
   
    result1 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 0, 1)) ,8)
    result2 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 1, 1)) ,8)
    result3 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 2, 1)) ,8)
    result4 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 3, 1)) ,8)
    result5 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 4, 1)) ,8)
    result6 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 5, 1)) ,8)
    result7 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 6, 1)) ,8)
    result8 = z3.Int2BV(z3.StrToCode(z3.SubString(result_string, 7, 1)) ,8)

    final_result = z3.Concat(result1, result2, result3, result4, result5, result6, result7, result8)

    configuration.stack_push( util.Uint(final_result) )
    return True