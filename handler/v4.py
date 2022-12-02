import logging
import z3
import util
import runtime
import memory
import math

log = logging.getLogger(__name__)


def shl_handle(configuration, instruction):
    """
    Opcode: 0x90
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A times 2^B, modulo 2^64
    Availability: v4
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = val2 << val1
    configuration.stack_push( util.Uint(result) )
    return True

def shr_handle(configuration, instruction):
    """
    Opcode: 0x91
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A divided by 2^B
    Availability: v4
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = val2 >> val1
    configuration.stack_push( util.Uint(result) )
    return True

def sqrt_handle(configuration, instruction):
    """
    Opcode: 0x92
    Stack: ..., A: uint64 -> ..., uint64
    The largest integer I such that I^2 <= A
    Availability: v4
    """
    val1 = configuration.stack_pop("uint")
    if not z3.is_bv_value(val1):
        log.debug("sqrt cannot handle dynamic value")
        return False
    z3_int_val = z3.BitVecVal(int(math.sqrt(val1.as_long())), 64)
    configuration.stack_push( util.Uint(z3_int_val) )
    return True

def exp_handle(configuration, instruction):
    """
    Opcode: 0x94
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A raised to the Bth power. Fail if A == B == 0 and on overflow
    Availability: v4
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    if not z3.is_bv_value(val1):
        log.debug("Z3 cannot handle non-polynomial problem")
        return False
    
    # 0 to the 0th power is mathematically undefined in Z3
    runtime.solver.add( z3.Or(val2 != 0, val1 != 0) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Exp(0,0) detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (exp_handle)")
        return False

    runtime.solver.add( z3.BV2Int(val2) ** z3.BV2Int(val1) <= 2 ** 64 - 1 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Exp opcode overflow")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (exp_handle)")
        return False
    
    result = z3.Int2BV(z3.BV2Int(val2) ** z3.BV2Int(val1), 64)
    configuration.stack_push( util.Uint(result) )
    return True


def bzero_handle(configuration, instruction):
    """
    Opcode: 0xaf
    Stack: ..., A: uint64 -> ..., []byte
    zero filled byte-array of length A
    Availability: v4
    """
    val1 = configuration.stack_pop("uint")
    if z3.is_bv_value(val1):
        result = z3.StringVal("\x00" * val1.as_long() )
        configuration.stack_push( util.Bytes(result) )
        return True
    else:
        log.debug("bzero cannot handle dynamic value")
        return False


def gload_handle(configuration, instruction):
    """
    Opcode: 0x3a {uint8 transaction group index} {uint8 position in scratch space to load from}
    Stack: ... -> ..., any
    Ith scratch space value of the Tth transaction in the current group
    Availability: v4
    Mode: Application
    """
    param0 = int(instruction["params"][0])
    param1 = int(instruction["params"][1])
    result_dict = util.Undefined({
        "array": "global_scratch_space",
        "op1": z3.BitVecVal( param0, 64 ),
        "op2": z3.BitVecVal( param1, 64 ),
    })
    configuration.stack_push( result_dict )
    return True


def gloads_handle(configuration, instruction):
    """
    Opcode: 0x3b {uint8 position in scratch space to load from}
    Stack: ..., A: uint64 -> ..., any
    Ith scratch space value of the Ath transaction in the current group
    Availability: v4
    Mode: Application
    """
    param0 = int(instruction["params"][0])
    val1 = configuration.stack_pop("uint")
    result_dict = util.Undefined({
        "array": "global_scratch_space",
        "op1": val1,
        "op2": z3.BitVecVal( param0, 64 ),
    })
    configuration.stack_push( result_dict )
    return True

def gaid_handle(configuration, instruction):
    """
    Opcode: 0x3c {uint8 transaction group index}
    Stack: ... -> ..., uint64
    ID of the asset or application created in the Tth transaction of the current group
    Availability: v4
    Mode: Application
    """
    param0 = int(instruction["params"][0])
    result = z3.Select(memory.gaid, z3.BitVecVal( param0, 64 ))
    configuration.stack_push( util.Uint(result) )
    return True


def gaids_handle(configuration, instruction):
    """
    Opcode: 0x3d
    Stack: ..., A: uint64 -> ..., uint64
    ID of the asset or application created in the Ath transaction of the current group
    Availability: v4
    Mode: Application
    """
    val1 = configuration.stack_pop("uint")
    result = z3.Select(memory.gaid, val1)
    configuration.stack_push( util.Uint(result) )
    return True


def divmodw_handle(configuration, instruction):
    """
    Opcode: 0x1f
    Stack: ..., A: uint64, B: uint64, C: uint64, D: uint64 -> ..., W: uint64, X: uint64, Y: uint64, Z: uint64
    W,X = (A,B / C,D); Y,Z = (A,B modulo C,D)
    Cost: 20
    Availability: v4
    """
    valD = configuration.stack_pop("uint")
    valC = configuration.stack_pop("uint")
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    valAB = z3.Concat(valA, valB)
    valCD = z3.Concat(valC, valD)

    runtime.solver.add( valCD != 0 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Divide by zero detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (divmodw_handle)")
        return False
    
    result1 = z3.UDiv(valAB, valCD)
    result2 = z3.URem(valAB, valCD)

    resultX = z3.Extract(63, 0, result1)
    resultW = z3.Extract(127, 64, result1)
    resultZ = z3.Extract(63, 0, result2)
    resultY = z3.Extract(127, 64, result2)

    configuration.stack_push( util.Uint(resultW) )
    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    configuration.stack_push( util.Uint(resultZ) )
    return True


def expw_handle(configuration, instruction):
    """
    Opcode: 0x95
    Stack: ..., A: uint64, B: uint64 -> ..., X: uint64, Y: uint64
    A raised to the Bth power as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low. Fail if A == B == 0 or if the results exceeds 2^128-1
    Cost: 10
    Availability: v4
    """
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")
    if not z3.is_bv_value(valB):
        log.debug("Z3 cannot handle non-polynomial problem")
        return False
    
    # 0 to the 0th power is mathematically undefined in Z3
    runtime.solver.add( z3.Or(valA != 0, valB != 0) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Expw(0,0) detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (expw_handle)")
        return False

    valA = z3.simplify(z3.BV2Int(valA)).as_long()
    valB = z3.simplify(z3.BV2Int(valB)).as_long()
    if valA ** valB > 2 ** 128 - 1:
        log.info("Expw opcode overflow")
        return False

    result = z3.BitVecVal(valA ** valB, 128)
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True


def BEQ_handle(configuration, instruction):
    """
    Opcode: 0xa8
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    1 if A is equal to B, else 0. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")
    result = z3.If(valA == valB, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def BNEQ_handle(configuration, instruction):
    """
    Opcode: 0xa9
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    0 if A is equal to B, else 1. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")
    result = z3.If(valA != valB, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True


def Badd_handle(configuration, instruction):
    """
    Opcode: 0xa0
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A plus B. A and B are interpreted as big-endian unsigned integers
    Cost: 10
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            configuration.stack_push( util.Bytes(valB) )
            return True
        if lengthB == 0:
            configuration.stack_push( util.Bytes(bvA) )
            return True

        result = z3.simplify(z3.BV2Int(bvA) + z3.BV2Int(bvB))
        final_length = 0
        tmpBV = z3.Int2BV(result, (lengthA + lengthB) * 8)

        for i in reversed(range(7, (lengthA + lengthB) * 8, 8)):
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
        log.info("Symbolic operand in b+ opcode")
        return False


def Bsub_handle(configuration, instruction):
    """
    Opcode: 0xa1
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A minus B. A and B are interpreted as big-endian unsigned integers. Fail on underflow.
    Cost: 10
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            if lengthB == 0:
                configuration.stack_push( util.Bytes(bvA) )
                return True
            else:
                log.info("b- opcode overflow")
                return False
        if lengthB == 0:
            configuration.stack_push( util.Bytes(bvA) )
            return True

        # Cannot use z3.BVSubNoUnderflow because the size of the two bitvectors may be different
        runtime.solver.add( z3.BV2Int(bvA) >= z3.BV2Int(bvB) )
        flag = runtime.solver.check()
        if flag == z3.unsat:
            log.info("b- opcode overflow")
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout (Bsub_handle)")
            return False

        result = z3.simplify(z3.BV2Int(bvA) - z3.BV2Int(bvB))        
        final_length = 0
        tmpBV = z3.Int2BV(result, (lengthA + lengthB) * 8)

        for i in reversed(range(7, (lengthA + lengthB) * 8, 8)):
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
        log.info("Symbolic operand in b- opcode")
        return False




def Bmul_handle(configuration, instruction):
    """
    Opcode: 0xa3
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A times B. A and B are interpreted as big-endian unsigned integers.
    Cost: 20
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            configuration.stack_push( util.Bytes(z3.StringVal("")) )
            return True
        if lengthB == 0:
            configuration.stack_push( util.Bytes(z3.StringVal("")) )
            return True
        
        result = z3.simplify(z3.BV2Int(bvA) * z3.BV2Int(bvB))        
        final_length = 0
        tmpBV = z3.Int2BV(result, (lengthA + lengthB) * 8)

        for i in reversed(range(7, (lengthA + lengthB) * 8, 8)):
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
        log.info("Symbolic operand in b* opcode")
        return False


def Bdiv_handle(configuration, instruction):
    """
    Opcode: 0xa2
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A divided by B (truncated division). A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
    Cost: 20
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            configuration.stack_push( util.Bytes(z3.StringVal("")) )
            return True
        if lengthB == 0:
            log.info("Divide by zero detected")
            return False

        runtime.solver.add( bvB != 0 )
        flag = runtime.solver.check()
        if flag == z3.unsat:
            log.info("Divide by zero detected")
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout (Bdiv_handle)")
            return False

        # Cannot use z3.UDiv because the size of the two bitvectors may be different
        result = z3.simplify(z3.BV2Int(bvA) / z3.BV2Int(bvB))
        final_length = 0
        tmpBV = z3.Int2BV(result, (lengthA + lengthB) * 8)

        for i in reversed(range(7, (lengthA + lengthB) * 8, 8)):
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
        log.info("Symbolic operand in b/ opcode")
        return False



def BLE_handle(configuration, instruction):
    """
    Opcode: 0xa6
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    1 if A is less than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        
        if lengthA == 0:
            bvA = z3.BitVecVal(0, 1)
        if lengthB == 0:
            bvB = z3.BitVecVal(0, 1)
        
        result = z3.If(z3.BV2Int(bvA) <= z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b<= opcode")
        return False

def BLT_handle(configuration, instruction):
    """
    Opcode: 0xa4
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    1 if A is less than B, else 0. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        
        if lengthA == 0:
            bvA = z3.BitVecVal(0, 1)
        if lengthB == 0:
            bvB = z3.BitVecVal(0, 1)
        
        result = z3.If(z3.BV2Int(bvA) < z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b< opcode")
        return False


def BGE_handle(configuration, instruction):
    """
    Opcode: 0xa7
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    1 if A is greater than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            bvA = z3.BitVecVal(0, 1)
        if lengthB == 0:
            bvB = z3.BitVecVal(0, 1)
        
        result = z3.If(z3.BV2Int(bvA) >= z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b>= opcode")
        return False


def BGT_handle(configuration, instruction):
    """
    Opcode: 0xa5
    Stack: ..., A: []byte, B: []byte -> ..., uint64
    1 if A is greater than B, else 0. A and B are interpreted as big-endian unsigned integers
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        
        if lengthA == 0:
            bvA = z3.BitVecVal(0, 1)
        if lengthB == 0:
            bvB = z3.BitVecVal(0, 1)
        
        result = z3.If(z3.BV2Int(bvA) > z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b> opcode")
        return False



def Brem_handle(configuration, instruction):
    """
    Opcode: 0xaa
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A modulo B. A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
    Cost: 20
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )

        if lengthA == 0:
            configuration.stack_push( util.Bytes(z3.StringVal("")) )
            return True
        if lengthB == 0:
            log.info("Divide by zero detected")
            return False
        
        runtime.solver.add( bvB != 0 )
        flag = runtime.solver.check()
        if flag == z3.unsat:
            log.info("Divide by zero detected")
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout (Bdiv_handle)")
            return False

        # Cannot use z3.URem because the size of the two bitvectors may be different
        result = z3.simplify(z3.BV2Int(bvA) % z3.BV2Int(bvB))
        final_length = 0
        tmpBV = z3.Int2BV(result, (lengthA + lengthB) * 8)

        for i in reversed(range(7, (lengthA + lengthB) * 8, 8)):
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
        log.info("Symbolic operand in b%% opcode")
        return False



def Bbit_or_handle(configuration, instruction):
    """
    Opcode: 0xab
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A bitwise-or B. A and B are zero-left extended to the greater of their lengths
    Cost: 6
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        max_length = max(lengthA * 8, lengthB * 8)
        final_string = z3.StringVal("")

        if max_length == 0:
            configuration.stack_push( util.Bytes(final_string) )
        else:
            finalBV = z3.Int2BV(z3.BV2Int(bvA), max_length) | z3.Int2BV(z3.BV2Int(bvB), max_length)
            for i in range(7, max_length, 8):
                final_string = z3.Concat(
                    z3.StrFromCode(z3.BV2Int(z3.Extract(i,i-7,finalBV))),
                    final_string
                )
            configuration.stack_push( util.Bytes(final_string) )
        return True
    else:
        log.info("Symbolic operand in b| opcode")
        return False


def Bbit_and_handle(configuration, instruction):
    """
    Opcode: 0xac
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A bitwise-and B. A and B are zero-left extended to the greater of their lengths
    Cost: 6
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        max_length = max(lengthA * 8, lengthB * 8)
        final_string = z3.StringVal("")

        if max_length == 0:
            configuration.stack_push( util.Bytes(final_string) )
        else:
            finalBV = z3.Int2BV(z3.BV2Int(bvA), max_length) & z3.Int2BV(z3.BV2Int(bvB), max_length)
            for i in range(7, max_length, 8):
                final_string = z3.Concat(
                    z3.StrFromCode(z3.BV2Int(z3.Extract(i,i-7,finalBV))),
                    final_string
                )
            configuration.stack_push( util.Bytes(final_string) )
        return True
    else:
        log.info("Symbolic operand in b& opcode")
        return False


def Bbit_xor_handle(configuration, instruction):
    """
    Opcode: 0xad
    Stack: ..., A: []byte, B: []byte -> ..., []byte
    A bitwise-xor B. A and B are zero-left extended to the greater of their lengths
    Cost: 6
    Availability: v4
    """
    valB = z3.simplify(configuration.stack_pop("bytes"))
    valA = z3.simplify(configuration.stack_pop("bytes"))
    bvA = None
    bvB = None

    if z3.is_string_value(valA) and z3.is_string_value(valB):
        lengthA = z3.simplify(z3.Length(valA)).as_long()
        lengthB = z3.simplify(z3.Length(valB)).as_long()
        for i in range(lengthA):
            if bvA == None:
                bvA = z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
            else:
                bvA = z3.Concat(
                    bvA,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valA, i, 1)) ,8)
                )
        for i in range(lengthB):
            if bvB == None:
                bvB = z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
            else:
                bvB = z3.Concat(
                    bvB,
                    z3.Int2BV(z3.StrToCode(z3.SubString(valB, i, 1)) ,8)
                )
        max_length = max(lengthA * 8, lengthB * 8)
        final_string = z3.StringVal("")

        if max_length == 0:
            configuration.stack_push( util.Bytes(final_string) )
        else:
            finalBV = z3.Int2BV(z3.BV2Int(bvA), max_length) ^ z3.Int2BV(z3.BV2Int(bvB), max_length)
            for i in range(7, max_length, 8):
                final_string = z3.Concat(
                    z3.StrFromCode(z3.BV2Int(z3.Extract(i,i-7,finalBV))),
                    final_string
                )
            configuration.stack_push( util.Bytes(final_string) )
        return True
    else:
        log.info("Symbolic operand in b^ opcode")
        return False



def Bbit_not_handle(configuration, instruction):
    """
    Opcode: 0xae
    Stack: ..., A: []byte -> ..., []byte
    A with all bits inverted
    Cost: 4
    Availability: v4
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

        max_length = lengthA * 8
        final_string = z3.StringVal("")

        if max_length == 0:
            configuration.stack_push( util.Bytes(final_string) )
        else:
            finalBV = ~bvA
            for i in range(7, max_length, 8):
                final_string = z3.Concat(
                    z3.StrFromCode(z3.BV2Int(z3.Extract(i,i-7,finalBV))),
                    final_string
                )
            configuration.stack_push( util.Bytes(final_string) )
        return True
    else:
        log.info("Symbolic operand in b~ opcode")
        return False


def bitlen_handle(configuration, instruction):
    """
    Opcode: 0x93
    Stack: ..., A -> ..., uint64
    The highest set bit in A. If A is a byte-array, it is interpreted as a big-endian unsigned integer. bitlen of 0 is 0, bitlen of 8 is 4
    Availability: v4
    """
    valA = configuration.stack_pop("original")

    if valA["type"] == "undefined":
        log.info("Undefined operand in bitlen opcode")
        return False

    valA = valA["value"]
    if z3.is_string_value(valA):
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
        if bvA == None:
            configuration.stack_push( util.Uint(z3.BitVecVal(0 ,64)) )
        else:
            value = z3.simplify(z3.BV2Int(bvA)).as_long()
            if value == 0:
                configuration.stack_push( util.Uint(z3.BitVecVal(0 ,64)) )
            else:
                for i in reversed(range(0, lengthA * 8)):
                    if value / (2 ** i) >= 1:
                        configuration.stack_push( util.Uint(z3.BitVecVal(i+1 ,64)) )
                        break
        return True

    elif z3.is_bv_value(valA):
        value = z3.simplify(z3.BV2Int(valA)).as_long()
        if value == 0:
            configuration.stack_push( util.Uint(z3.BitVecVal(0 ,64)) )
        else:
            for i in reversed(range(0, 64)):
                if value / (2 ** i) >= 1:
                    configuration.stack_push( util.Uint(z3.BitVecVal(i+1 ,64)) )
                    break
        return True
    else:
        log.info("Symbolic operand in bitlen opcode")
        return False

