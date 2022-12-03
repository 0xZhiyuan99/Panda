import logging
import z3
import util
import runtime
import memory
import re
import base64
import setting
from .debug import show_backtrace

log = logging.getLogger(__name__)

def swap_handle(configuration, instruction):
    """
    Opcode: 0x4c
    Stack: ..., A, B -> ..., B, A
    swaps A and B on stack
    Availability: v3
    """
    val_dict1 = configuration.stack_pop("original")
    val_dict2 = configuration.stack_pop("original")
    configuration.stack_push(val_dict1)
    configuration.stack_push(val_dict2)
    return True

def dig_handle(configuration, instruction):
    """
    Opcode: 0x4b {uint8 depth}
    Stack: ..., A, [N items] -> ..., A, [N items], A
    Nth value from the top of the stack. dig 0 is equivalent to dup
    Availability: v3
    """
    param0 = int(instruction["params"][0])
    val_dict1 = configuration.stack_get(-1-param0)
    configuration.stack_push(val_dict1)
    return True

def assert_handle(configuration, instruction):
    """
    Opcode: 0x44
    Stack: ..., A: uint64 -> ...
    immediately fail unless A is a non-zero number
    Availability: v3
    """
    val1 = configuration.stack_pop("uint")
    runtime.solver.add( val1 != 0 )
    flag = runtime.solver.check()
    if flag == z3.sat:
        return True
    elif flag == z3.unknown:
        log.info("Z3 timeout (assert_handle)")
    return False


def gtxns_handle(configuration, instruction):
    """
    Opcode: 0x38 {uint8 transaction field index}
    Stack: ..., A: uint64 -> ..., any
    field F of the Ath transaction in the current group
    Availability: v3
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("uint")
    configuration.opcode_record["gtxn_index"].append( val1 )

    if param0 == "Sender":
        if setting.IS_SMART_CONTRACT:
            # Arbitrary sender address is OK in smart contract
            dict_result = util.Bytes( z3.StringVal( setting.sender_address ) )
        else:
            dict_result = util.Bytes( z3.Select(memory.gtxn_Sender, val1) )
    elif param0 == "Fee":
        dict_result = util.Uint( z3.Select(memory.gtxn_Fee, val1) )
    elif param0 == "FirstValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValid, val1) )
    elif param0 == "FirstValidTime":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValidTime, val1) )
    elif param0 == "LastValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_LastValid, val1) )
    elif param0 == "Note":
        runtime.solver.add(z3.Length( z3.Select(memory.gtxn_Note, val1) ) <= 1024)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Note, val1) )
    elif param0 == "Lease":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Lease, val1) )
    elif param0 == "Receiver":
        configuration.opcode_record["gtxn_pay_index"].append( val1 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, val1) )
    elif param0 == "Amount":
        configuration.opcode_record["gtxn_pay_index"].append( val1 )
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, val1) )
    elif param0 == "CloseRemainderTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_CloseRemainderTo, val1) )
    elif param0 == "VotePK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_VotePK, val1) )
    elif param0 == "SelectionPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_SelectionPK, val1) )
    elif param0 == "VoteFirst":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteFirst, val1) )
    elif param0 == "VoteLast":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteLast, val1) )
    elif param0 == "VoteKeyDilution":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteKeyDilution, val1) )
    elif param0 == "Type":
        configuration.opcode_record["gtxn_pay_index"].append( val1 )
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_Type, val1) )
    elif param0 == "TypeEnum":
        configuration.opcode_record["gtxn_pay_index"].append( val1 )
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Uint( z3.Select(memory.gtxn_TypeEnum, val1) )
    elif param0 == "XferAsset":
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Uint( z3.Select(memory.gtxn_XferAsset, val1) )
    elif param0 == "AssetAmount":
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Uint( z3.Select(memory.gtxn_AssetAmount, val1) )
    elif param0 == "AssetSender":
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, val1) )
    elif param0 == "AssetReceiver":
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, val1) )
    elif param0 == "AssetCloseTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetCloseTo, val1) )
    elif param0 == "GroupIndex":
        dict_result = util.Uint( val1 )
    elif param0 == "TxID":
        # Arbitrary transaction ID is OK
        dict_result = util.Bytes( z3.StringVal( "HUXPAWEPYZNL2WZXNFL7AZCAFWEHUUP3R2667BFJLFA6YHFLWALA" ) )
    elif param0 == "ApplicationID":
        dict_result = util.Uint( z3.Select(memory.gtxn_ApplicationID, val1) )
    elif param0 == "OnCompletion":
        dict_result = util.Uint( z3.Select(memory.gtxn_OnCompletion, val1) )
    elif param0 == "NumAppArgs":
        runtime.solver.add( z3.Select(memory.gtxn_NumAppArgs, val1) <= 16 )
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAppArgs, val1) )
    elif param0 == "NumAccounts":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAccounts, val1) )
    elif param0 == "ApprovalProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ApprovalProgram, val1) )
    elif param0 == "ClearStateProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ClearStateProgram, val1) )
    elif param0 == "RekeyTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_RekeyTo, val1) )
    elif param0 == "ConfigAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAsset, val1) )
    elif param0 == "ConfigAssetTotal":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetTotal, val1) )
    elif param0 == "ConfigAssetDecimals":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDecimals, val1) )
    elif param0 == "ConfigAssetDefaultFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDefaultFrozen, val1) )
    elif param0 == "ConfigAssetUnitName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetUnitName, val1) )
    elif param0 == "ConfigAssetName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetName, val1) )
    elif param0 == "ConfigAssetURL":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetURL, val1) )
    elif param0 == "ConfigAssetMetadataHash":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetMetadataHash, val1) )
    elif param0 == "ConfigAssetManager":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetManager, val1) )
    elif param0 == "ConfigAssetReserve":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetReserve, val1) )
    elif param0 == "ConfigAssetFreeze":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetFreeze, val1) )
    elif param0 == "ConfigAssetClawback":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetClawback, val1) )
    elif param0 == "FreezeAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAsset, val1) )
    elif param0 == "FreezeAssetAccount":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetAccount, val1) )
    elif param0 == "FreezeAssetFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetFrozen, val1) )
    elif param0 == "NumAssets":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAssets, val1) )
    elif param0 == "NumApplications":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumApplications, val1) )
    elif param0 == "GlobalNumUint":
        dict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumUint, val1) )
    elif param0 == "GlobalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumByteSlice, val1) )
    elif param0 == "LocalNumUint":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumUint, val1) )
    elif param0 == "LocalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumByteSlice, val1) )
    elif param0 == "ExtraProgramPages":
        dict_result = util.Uint( z3.Select(memory.gtxn_ExtraProgramPages, val1) )
    elif param0 == "Nonparticipation":
        dict_result = util.Uint( z3.Select(memory.gtxn_Nonparticipation, val1) )
    elif param0 == "Logs":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Logs, val1) )
    elif param0 == "NumLogs":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumLogs, val1) )
    elif param0 == "CreatedAssetID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedAssetID, val1) )
    elif param0 == "CreatedApplicationID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedApplicationID, val1) )
    elif param0 == "LastLog":
        dict_result = util.Bytes( z3.Select(memory.gtxn_LastLog, val1) )
    elif param0 == "StateProofPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_StateProofPK, val1) )
    else:
        log.error("unrecognised opcode: <gtxns {} {}>".format(val1, param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


def gtxnsa_handle(configuration, instruction):
    """
    Opcode: 0x39 {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ..., A: uint64 -> ..., any
    Ith value of the array field F from the Ath transaction in the current group
    Availability: v3
    """
    val1 = configuration.stack_pop("uint")
    param0 = instruction["params"][0]
    param1 = z3.BitVecVal( int(instruction["params"][1]), 64 )

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, val1, param1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, val1, param1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, val1, param1) )
    elif param0 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, val1, param1) )
    elif param0 == "Logs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Logs, val1, param1) )
    elif param0 == "ApprovalProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApprovalProgramPages, val1, param1) )
    elif param0 == "ClearStateProgramPages":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ClearStateProgramPages, val1, param1) )
    else:
        log.error("unrecognised opcode: <gtxnsa {} {} {}>".format(val1, param0, param1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


def pushint_handle(configuration, instruction):
    """
    Opcode: 0x81 {varuint int}
    Stack: ... -> ..., uint64
    immediate UINT
    Availability: v3
    """
    param0 = int(instruction["params"][0])
    result = z3.BitVecVal(param0, 64)
    configuration.stack_push( util.Uint(result) )
    return True

def pushbytes_handle(configuration, instruction):
    """
    Opcode: 0x80 {varuint length} {bytes}
    Stack: ... -> ..., []byte
    immediate BYTES
    Availability: v3
    """
    param0 = instruction["params"][0]
    string_match = re.match("\"(.*)\"", param0)
    base64_match = re.match("base64\((.*)\)", param0)

    if string_match != None:
        result = z3.StringVal( string_match.group(1) )
    elif base64_match != None:
        result = z3.StringVal( base64.b64decode( base64_match.group(1) ).decode("Latin-1") )
    else:
        result = z3.StringVal( bytes.fromhex(param0[2:]).decode("Latin-1") )

    configuration.stack_push( util.Bytes(result) )
    return True


def min_balance_handle(configuration, instruction):
    """
    Opcode: 0x78
    Stack: ..., A -> ..., uint64
    get minimum required balance for account A, in microalgos.
    Availability: v3
    Mode: Application
    """
    val1 = configuration.stack_pop("original")
    if val1["type"] == "undefined":
        log.info("min_balance_handle gets undefined variable")
        return False
    elif val1["type"] == "uint":
        result = z3.Select(memory.min_balance_array_uint, val1["value"])
    elif val1["type"] == "bytes":
        result = z3.Select(memory.min_balance_array_bytes, val1["value"])
    runtime.solver.add(result >= 100000)
    configuration.stack_push( util.Uint(result) )
    return True



def getbyte_handle(configuration, instruction):
    """
    Opcode: 0x55
    Stack: ..., A: []byte, B: uint64 -> ..., uint64
    Bth byte of A, as an integer
    Availability: v3
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("bytes")
    
    result = z3.Int2BV(z3.StrToCode(z3.SubString(val2, z3.BV2Int(val1), 1)), 64)
    configuration.stack_push( util.Uint(result) )
    return True

def setbyte_handle(configuration, instruction):
    """
    Opcode: 0x56
    Stack: ..., A: []byte, B: uint64, C: uint64 -> ..., []byte
    Copy of A with the Bth byte set to small integer (between 0..255) C. If B is greater than or equal to the array length, the program fails
    Availability: v3
    """
    valC = configuration.stack_pop("uint")
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("bytes")
    
    result = z3.Concat(
        z3.SubString(valA, 0, z3.BV2Int(valB)),
        z3.StrFromCode(z3.BV2Int(valC)),
        z3.SubString(valA, z3.BV2Int(valB)+1, z3.Length(valA)-z3.BV2Int(valB)),
    )

    configuration.stack_push( util.Bytes(result) )
    return True


def getbit_handle(configuration, instruction):
    """
    Opcode: 0x53
    Stack: ..., A, B: uint64 -> ..., uint64
    Bth bit of (byte-array or integer) A. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
    Availability: v3
    """
    valB = z3.simplify(configuration.stack_pop("uint"))
    valA = configuration.stack_pop("original")

    if valA["type"] == "undefined":
        log.info("Undefined operand in getbit opcode")
        return False

    valA = valA["value"]
    if z3.is_string_value(valA) and z3.is_bv_value(valB):
        bvA = None
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        
        if lengthA * 8 <= z3.simplify(z3.BV2Int(valB)).as_long():
            log.info("Invalid getbit opcode")
            return False
        remainder = z3.simplify(z3.BV2Int(valB) % 8).as_long()
        quotient = z3.simplify(z3.BV2Int(valB) / 8).as_long()
        targetBV = z3.Extract(quotient * 8 + 7, quotient * 8, bvA)
        result = z3.simplify(z3.If( (targetBV & (1 << (7 - remainder))) > 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)))
        configuration.stack_push( util.Uint(result) )
        return True
    elif z3.is_bv_value(valA) and z3.is_bv_value(valB):
        if 64 <= z3.simplify(z3.BV2Int(valB)).as_long():
            log.info("Invalid getbit opcode")
            return False

        remainder = z3.simplify(z3.BV2Int(valB) % 8).as_long()
        quotient = z3.simplify(z3.BV2Int(valB) / 8).as_long()
        targetBV = z3.Extract(quotient * 8 + 7, quotient * 8, valA)
        result = z3.simplify(z3.If( (targetBV & (1 << remainder)) > 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in getbit opcode")
        return False


def setbit_handle(configuration, instruction):
    """
    Opcode: 0x54
    Stack: ..., A, B: uint64, C: uint64 -> ..., any
    Copy of (byte-array or integer) A, with the Bth bit set to (0 or 1) C. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
    Availability: v3
    """
    valC = z3.simplify(configuration.stack_pop("uint"))
    valB = z3.simplify(configuration.stack_pop("uint"))
    valA = configuration.stack_pop("original")

    if valA["type"] == "undefined":
        log.info("Undefined operand in setbit opcode")
        return False

    valA = valA["value"]
    if z3.is_string_value(valA) and z3.is_bv_value(valB):
        bvA = None
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        
        if lengthA * 8 <= z3.simplify(z3.BV2Int(valB)).as_long():
            log.info("Invalid setbit opcode")
            return False
        remainder = z3.simplify(z3.BV2Int(valB) % 8).as_long()
        quotient = z3.simplify(z3.BV2Int(valB) / 8).as_long()
        targetBV = z3.Extract(quotient * 8 + 7, quotient * 8, bvA)
        resultBV = targetBV | (1 << (7 - remainder))

        result = z3.Concat(
            z3.SubString(valA, 0, quotient),
            z3.StrFromCode(z3.BV2Int(resultBV)),
            z3.SubString(valA, quotient+1, z3.Length(valA)-quotient),
        )

        configuration.stack_push( util.Bytes(result) )
        return True
    elif z3.is_bv_value(valA) and z3.is_bv_value(valB):
        if 64 <= z3.simplify(z3.BV2Int(valB)).as_long():
            log.info("Invalid setbit opcode")
            return False

        remainder = z3.simplify(z3.BV2Int(valB) % 8).as_long()
        quotient = z3.simplify(z3.BV2Int(valB) / 8).as_long()
        targetBV = z3.Extract(quotient * 8 + 7, quotient * 8, valA)
        resultBV = targetBV | (1 << remainder)

        if quotient > 0:
            result = z3.Concat(
                z3.Extract(63, (quotient+1)*8, valA),
                resultBV,
                z3.Extract(quotient * 8 - 1, 0, valA),
            )
        else:
            result = z3.Concat(
                z3.Extract(63, (quotient+1)*8, valA),
                resultBV
            )

        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in setbit opcode")
        return False



def select_handle(configuration, instruction):
    """
    Opcode: 0x4d
    Stack: ..., A, B, C: uint64 -> ..., A or B
    selects one of two values based on top-of-stack: B if C != 0, else A
    Availability: v3
    """
    valC = configuration.stack_pop("uint")
    valB = configuration.stack_pop("original")
    valA = configuration.stack_pop("original")

    if valA["type"] != valB["type"]:
        # Z3 cannot handle different type values in the if statement
        log.info("Different operand type of select opcode")
        return False
    
    result = z3.If(valC != 0, valB["value"], valA["value"])
    if valA["type"] == "uint":
        configuration.stack_push( util.Uint(result) )
    else:
        configuration.stack_push( util.Bytes(result) )
    return True
