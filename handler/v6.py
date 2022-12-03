import logging
import z3
import util
import runtime
import memory
import math

log = logging.getLogger(__name__)


def acct_params_get_handle(configuration, instruction):
    """
    Opcode: 0x73 {uint8 account params field index}
    Stack: ..., A → ..., X: any, Y: uint64
    X is field F from account A. Y is 1 if A owns positive algos, else 0
    Availability: v6
    Mode: Application
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("bytes")

    if param0 == "AcctBalance":
        result = z3.Select(memory.balance_array_bytes, val1)
        runtime.solver.add(result >= 100000)
        configuration.stack_push( util.Uint(result) )
    elif param0 == "AcctMinBalance":
        result = z3.Select(memory.min_balance_array_bytes, val1)
        runtime.solver.add(result >= 100000)
        configuration.stack_push( util.Uint(result) )
    if param0 == "AcctAuthAddr":
        result = z3.Select(memory.AcctAuthAddr_array_bytes, val1)
        configuration.stack_push( util.Bytes(result) )

    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    return True

def itxn_next_handle(configuration, instruction):
    """
    Opcode: 0xb6
    Stack: ... -> ...
    begin preparation of a new inner transaction in the same transaction group
    Availability: v6
    Mode: Application
    """
    runtime.itxn_index += 1
    return True


def gitxn_handle(configuration, instruction):
    """
    Opcode: 0xb7 {uint8 transaction group index} {uint8 transaction field index}
    Stack: ... → ..., any
    field F of the Tth transaction in the last inner group submitted
    Availability: v6
    Mode: Application
    """

    group = int(instruction["params"][0])
    field = instruction["params"][1]

    if field not in runtime.itxn_field[group]:
        log.info("Invalid gitxn opcode")
        return False

    configuration.stack_push( runtime.itxn_field[group][field] )
    return True


def gitxna_handle(configuration, instruction):
    """
    Opcode: 0xb8 {uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ... → ..., any
    Ith value of the array field F from the Tth transaction in the last inner group submitted
    Availability: v6
    Mode: Application
    """
    group = int(instruction["params"][0])
    field = instruction["params"][1]
    array_index = int(instruction["params"][2])

    if field not in ["ApplicationArgs", "Accounts", "Assets", "Applications", "Logs", "ApprovalProgramPages", "ClearStateProgramPages"]:
        log.info("Invalid gitxna opcode")
        return False

    try:
        configuration.stack_push( runtime.itxn_field[group][field][array_index] )
    except:
        log.info("Invalid gitxna opcode")
        return False

    return True


def itxnas_handle(configuration, instruction):
    """
    Opcode: 0xc5 {uint8 transaction field index}
    Stack: ..., A: uint64 → ..., any
    Ath value of the array field F of the last inner transaction
    Availability: v6
    Mode: Application
    """
    field = instruction["params"][0]
    valA = configuration.stack_pop("uint")

    if not z3.is_bv_value(valA):
        log.debug("Symbolic value in itxnas opcode")
        return False

    if field not in ["ApplicationArgs", "Accounts", "Assets", "Applications", "Logs", "ApprovalProgramPages", "ClearStateProgramPages"]:
        log.info("Invalid itxnas opcode")
        return False

    try:
        configuration.stack_push( runtime.itxn_field[runtime.itxn_index][field][valA.as_long()] )
    except:
        log.info("Invalid itxnas opcode")
        return False

    return True


def gitxnas_handle(configuration, instruction):
    """
    Opcode: 0xc6 {uint8 transaction group index} {uint8 transaction field index}
    Stack: ..., A: uint64 → ..., any
    Ath value of the array field F from the Tth transaction in the last inner group submitted
    Availability: v6
    Mode: Application
    """
    group = int(instruction["params"][0])
    field = instruction["params"][1]
    valA = configuration.stack_pop("uint")

    if not z3.is_bv_value(valA):
        log.debug("Symbolic value in gitxnas opcode")
        return False

    if field not in ["ApplicationArgs", "Accounts", "Assets", "Applications", "Logs", "ApprovalProgramPages", "ClearStateProgramPages"]:
        log.info("Invalid gitxnas opcode")
        return False

    try:
        configuration.stack_push( runtime.itxn_field[group][field][valA.as_long()] )
    except:
        log.info("Invalid gitxnas opcode")
        return False

    return True


def bsqrt_handle(configuration, instruction):
    """
    Opcode: 0x96
    Stack: ..., A: []byte → ..., []byte
    The largest integer I such that I^2 <= A. A and I are interpreted as big-endian unsigned integers
    Cost: 40
    Availability: v6
    """
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None

    if z3.is_string_value(valA):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )

        if lengthA == 0:
            configuration.stack_push( util.Bytes(z3.StringVal("")) )
            return True
        
        result = z3.IntVal(math.sqrt( z3.simplify(z3.BV2Int(bvA)).as_long() ))
        final_length = 0
        tmpBV = z3.Int2BV(result, lengthA * 8)

        for i in reversed(range(7, lengthA * 8, 8)):
            if z3.simplify(z3.BV2Int((z3.Extract(i,i-7,tmpBV)))).as_long() != 0:
                final_length = i + 1
                break
        
        final_string = z3.StringVal("")

        if final_length == 0:
            configuration.stack_push( util.Bytes(final_string) )
        else:
            finalBV = z3.Int2BV(result, final_length)
            for i in range(7, final_length, 8):
                final_string = z3.Concat(
                    z3.StrFromCode(z3.BV2Int(z3.Extract(i,i-7,finalBV))),
                    final_string
                )
            configuration.stack_push( util.Bytes(final_string) )
        return True
    else:
        log.info("Symbolic operand in bsqrt opcode")
        return False


def divw_handle(configuration, instruction):
    """
    Opcode: 0x97
    Stack: ..., A: uint64, B: uint64, C: uint64 → ..., uint64
    A,B / C. Fail if C == 0 or if result overflows.
    Availability: v6
    """

    valC = configuration.stack_pop("uint")
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    valAB = z3.Concat(valA, valB)
    valCD = z3.Concat(z3.BitVecVal(0, 64), valC)

    runtime.solver.add( valCD != 0 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Divide by zero detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (divw_handle)")
        return False
    
    result1 = z3.UDiv(valAB, valCD)
    resultX = z3.Extract(63, 0, result1)
    resultW = z3.Extract(127, 64, result1)

    runtime.solver.add( resultW == 0 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("divw opcode overflow")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (divw_handle)")
        return False

    configuration.stack_push( util.Uint(resultX) )
    return True


def gloadss_handle(configuration, instruction):
    """
    Opcode: 0xc4
    Stack: ..., A: uint64, B: uint64 → ..., any
    Bth scratch space value of the Ath transaction in the current group
    Availability: v6
    Mode: Application
    """
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")
    result_dict = util.Undefined({
        "array": "global_scratch_space",
        "op1": valA,
        "op2": valB,
    })
    configuration.stack_push( result_dict )
    return True