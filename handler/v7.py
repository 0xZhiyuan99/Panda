import logging
import z3
import util
import runtime

log = logging.getLogger(__name__)


def replace2_handle(configuration, instruction):
    """
    Opcode: 0x5c {uint8 start position}
    Stack: ..., A: []byte, B: []byte → ..., []byte
    Copy of A with the bytes starting at S replaced by the bytes of B. Fails if S+len(B) exceeds len(A)
    replace2 can be called using replace with 1 immediate.
    Availability: v7
    """
    start = int(instruction["params"][0])
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(valA) >= z3.Length(valB) + z3.IntVal(start) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid replace2 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (replace2_handle)")
        return False

    result = z3.Concat(
        z3.SubString(valA, 0, start), 
        valB,
        z3.SubString(valA, start + z3.Length(valB), z3.Length(valA) - z3.Length(valB) - z3.IntVal(start))
    )

    configuration.stack_push( util.Bytes(result) )
    return True

def replace3_handle(configuration, instruction):
    """
    Opcode: 0x5d
    Stack: ..., A: []byte, B: uint64, C: []byte → ..., []byte
    Copy of A with the bytes starting at B replaced by the bytes of C. Fails if B+len(C) exceeds len(A)
    replace3 can be called using replace with no immediates.
    Availability: v7
    """
    valC = configuration.stack_pop("bytes")
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("bytes")

    runtime.solver.add( z3.Length(valA) >= z3.BV2Int(valB) + z3.Length(valC) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Invalid replace3 opcode")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (replace3_handle)")
        return False

    result = z3.Concat(
        z3.SubString(valA, 0, z3.BV2Int(valB)), 
        valC,
        z3.SubString(valA, z3.BV2Int(valB) + z3.Length(valC), z3.Length(valA) - z3.Length(valC) - z3.BV2Int(valB))
    )

    configuration.stack_push( util.Bytes(result) )
    return True

def base64_decode_handle(configuration, instruction):
    """
    Opcode: 0x5e {uint8 encoding index}
    Stack: ..., A: []byte → ..., []byte
    decode A which was base64-encoded using encoding E. Fail if A is not base64 encoded with encoding E
    Cost: 1 + 1 per 16 bytes of A
    Availability: v7
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.String( "base64_decode({})".format(val1.__str__()) )

    configuration.stack_push( util.Bytes(result) )
    log.info("Use symbolic base64 variable")
    return True

def json_ref_handle(configuration, instruction):
    """
    Opcode: 0x5f {uint8 return type}
    Stack: ..., A: []byte, B: []byte → ..., any
    key B's value, of type R, from a valid utf-8 encoded json object A
    Cost: 25 + 2 per 7 bytes of A
    Availability: v7
    """
    param0 = instruction["params"][0]
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")

    if param0 == "JSONString" or param0 == "JSONObject":
        result = z3.String( "json_ref({},{})".format(valA.__str__(), valB.__str__()) )
        configuration.stack_push( util.Bytes(result) )
    elif param0 == "JSONUint64":
        result = z3.BitVec( "json_ref({},{})".format(valA.__str__(), valB.__str__()), 64)
        configuration.stack_push( util.Uint(result) )
    else:
        log.error("unrecognised opcode: <json_ref {}>".format(param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    log.info("Use symbolic json variable")
    return True

def vrf_verify_handle(configuration, instruction):
    """
    Opcode: 0xd0 {uint8 parameters index}
    Stack: ..., A: []byte, B: []byte, C: []byte → ..., X: []byte, Y: uint64
    Verify the proof B of message A against pubkey C. Returns vrf output and verification flag.
    Cost: 5700
    Availability: v7
    """
    valC = configuration.stack_pop("bytes")
    valB = configuration.stack_pop("bytes")
    valA = configuration.stack_pop("bytes")
    result = z3.String( "vrf_verify({},{},{})".format(valA.__str__(),valB.__str__(),valC.__str__()) )

    configuration.stack_push( util.Bytes(result))
    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))

    log.info("Use symbolic hash variable")
    return True

def block_handle(configuration, instruction):
    """
    Opcode: 0xd1 {uint8 block field}
    Stack: ..., A: uint64 → ..., any
    field F of block A. Fail unless A falls between txn.LastValid-1002 and txn.FirstValid (exclusive)
    Availability: v7
    """
    param0 = instruction["params"][0]
    valA = configuration.stack_pop("uint")
    
    if param0 == "BlkSeed":
        result = z3.String( "BlkSeed({})".format(valA.__str__()) )
        configuration.stack_push( util.Bytes(result))
    elif param0 == "BlkTimestamp":
        result = z3.BitVec( "BlkTimestamp({})".format(valA.__str__()), 64)
        configuration.stack_push( util.Uint(result))
    else:
        log.error("unrecognised opcode: <block {}>".format(param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    return True

def ed25519verify_bare_handle(configuration, instruction):
    """
    Opcode: 0x84
    Stack: ..., A: []byte, B: []byte, C: []byte → ..., uint64
    for (data A, signature B, pubkey C) verify the signature of the data against the pubkey => {0 or 1}
    Cost: 1900
    Availability: v7
    """
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")

    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    return True

def sha3_256_handle(configuration, instruction):
    """
    Opcode: 0x98
    Stack: ..., A: []byte → ..., []byte
    SHA3_256 hash of value A, yields [32]byte
    Cost: 130
    Availability: v7
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.String( "sha3_256({})".format(val1.__str__()) )

    # The hash value is 32 bytes
    runtime.solver.add( z3.Length(result) == 32 )
    configuration.stack_push( util.Bytes(result) )
    log.info("Use symbolic hash variable")
    return True