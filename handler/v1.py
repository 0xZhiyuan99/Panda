import logging
import z3
import util
import runtime
import memory
import setting

log = logging.getLogger(__name__)



def intcblock_handle(configuration, instruction):
    """
    Opcode: 0x20 {varuint length} [{varuint value}, ...]
    Stack: ... -> ...
    prepare block of uint64 constants for use by intc
    """
    uint_block = []
    for uint_param in instruction["params"]:
        if int(uint_param) < 0:
            log.error("Invalid intcblock")
            exit(runtime.INVALID_INTCBLOCK)
        if int(uint_param) >= 2 ** 64:
            log.error("Invalid intcblock")
            exit(runtime.INVALID_INTCBLOCK)
        val = z3.BitVecVal(int(uint_param), 64)
        uint_block.append(val)
    configuration.uint_block = uint_block
    return True

def bytecblock_handle(configuration, instruction):
    """
    Opcode: 0x26 {varuint length} [({varuint value length} bytes), ...]
    Stack: ... -> ...
    prepare block of byte-array constants for use by bytec
    """
    bytes_block = []
    try:
        for byte_param in instruction["params"]:
            val = z3.StringVal( bytes.fromhex(byte_param[2:]).decode("Latin-1") )
            bytes_block.append(val)
    except:
        log.error("Invalid bytecblock")
        exit(runtime.INVALID_BYTEC_BLOCK)
    configuration.bytes_block = bytes_block
    return True


def intc_handle(configuration, instruction):
    """
    Opcode: 0x21 {uint8 int constant index}
    Stack: ... -> ..., uint64
    Ith constant from intcblock
    """
    param0 = int(instruction["params"][0])
    uint_val = configuration.get_uint(param0)
    configuration.stack_push(util.Uint(uint_val))
    return True

def intc_0_handle(configuration, instruction):
    """
    Opcode: 0x22
    Stack: ... -> ..., uint64
    constant 0 from intcblock
    """
    uint_val = configuration.get_uint(0)
    configuration.stack_push(util.Uint(uint_val))
    return True


def intc_1_handle(configuration, instruction):
    """
    Opcode: 0x23
    Stack: ... -> ..., uint64
    constant 1 from intcblock
    """
    uint_val = configuration.get_uint(1)
    configuration.stack_push(util.Uint(uint_val))
    return True

def intc_2_handle(configuration, instruction):
    """
    Opcode: 0x24
    Stack: ... -> ..., uint64
    constant 2 from intcblock
    """
    uint_val = configuration.get_uint(2)
    configuration.stack_push(util.Uint(uint_val))
    return True


def intc_3_handle(configuration, instruction):
    """
    Opcode: 0x25
    Stack: ... -> ..., uint64
    constant 3 from intcblock
    """
    uint_val = configuration.get_uint(3)
    configuration.stack_push(util.Uint(uint_val))
    return True

def bytec_handle(configuration, instruction):
    """
    Opcode: 0x27 {uint8 byte constant index}
    Stack: ... -> ..., []byte
    Ith constant from bytecblock
    """
    param0 = int(instruction["params"][0])
    bytes_val = configuration.get_bytes(param0)
    configuration.stack_push(util.Bytes(bytes_val))
    return True

def bytec_0_handle(configuration, instruction):
    """
    Opcode: 0x28
    Stack: ... -> ..., []byte
    constant 0 from bytecblock
    """
    bytes_val = configuration.get_bytes(0)
    configuration.stack_push(util.Bytes(bytes_val))
    return True


def bytec_1_handle(configuration, instruction):
    """
    Opcode: 0x29
    Stack: ... -> ..., []byte
    constant 1 from bytecblock
    """
    bytes_val = configuration.get_bytes(1)
    configuration.stack_push(util.Bytes(bytes_val))
    return True

def bytec_2_handle(configuration, instruction):
    """
    Opcode: 0x2a
    Stack: ... -> ..., []byte
    constant 2 from bytecblock
    """
    bytes_val = configuration.get_bytes(2)
    configuration.stack_push(util.Bytes(bytes_val))
    return True

def bytec_3_handle(configuration, instruction):
    """
    Opcode: 0x2b
    Stack: ... -> ..., []byte
    constant 3 from bytecblock
    """
    bytes_val = configuration.get_bytes(3)
    configuration.stack_push(util.Bytes(bytes_val))
    return True

def add_handle(configuration, instruction):
    """
    Opcode: 0x08
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A plus B. Fail on overflow.
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    runtime.solver.add( z3.BVAddNoOverflow(val2, val1, False) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Integer addition overflow detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (add_handle)")
        return False
    
    result = val2 + val1
    configuration.stack_push( util.Uint(result) )
    return True

def sub_handle(configuration, instruction):
    """
    Opcode: 0x09
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A minus B. Fail if B > A.
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    runtime.solver.add( z3.BVSubNoUnderflow(val2, val1, False) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Integer subtraction underflow detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (sub_handle)")
        return False
    
    result = val2 - val1
    configuration.stack_push( util.Uint(result) )
    return True

def mul_handle(configuration, instruction):
    """
    Opcode: 0x0b
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A times B. Fail on overflow.
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    runtime.solver.add( z3.BVMulNoOverflow(val2, val1, False) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Integer multiplication overflow detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (mul_handle)")
        return False
    
    result = val2 * val1
    configuration.stack_push( util.Uint(result) )
    return True


def div_handle(configuration, instruction):
    """
    Opcode: 0x0a
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A divided by B (truncated division). Fail if B == 0.
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    runtime.solver.add( val1 != 0 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Divide by zero detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (div_handle)")
        return False
    
    result = z3.UDiv(val2, val1)
    configuration.stack_push( util.Uint(result) )
    return True


def rem_handle(configuration, instruction):
    """
    Opcode: 0x18
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A modulo B. Fail if B == 0.
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    runtime.solver.add( val1 != 0 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("The remainder is zero")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (rem_handle)")
        return False
    
    result = z3.URem(val2, val1)
    configuration.stack_push( util.Uint(result) )
    return True


def dup_handle(configuration, instruction):
    """
    Opcode: 0x49
    Stack: ..., A -> ..., A, A
    duplicate A
    """
    # Note that the duplicate value is a reference of the original value
    val1 = configuration.stack_get(-1)
    configuration.stack_push(val1)
    return True


def EQ_handle(configuration, instruction):
    """
    Opcode: 0x12
    Stack: ..., A, B -> ..., uint64
    A is equal to B => {0 or 1}
    """
    val1, val2 = configuration.stack_pop2()
    result = z3.If(val2 == val1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def NEQ_handle(configuration, instruction):
    """
    Opcode: 0x13
    Stack: ..., A, B -> ..., uint64
    A is not equal to B => {0 or 1}
    """
    val1, val2 = configuration.stack_pop2()
    result = z3.If(val2 != val1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True


def LT_handle(configuration, instruction):
    """
    Opcode: 0x0c
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A less than B => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If(z3.ULT(val2, val1), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def GT_handle(configuration, instruction):
    """
    Opcode: 0x0d
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A greater than B => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If(z3.UGT(val2, val1), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def LE_handle(configuration, instruction):
    """
    Opcode: 0x0e
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A less than or equal to B => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If(z3.ULE(val2, val1), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True


def GE_handle(configuration, instruction):
    """
    Opcode: 0x0f
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A greater than or equal to B => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If(z3.UGE(val2, val1), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def arg_i_handle(configuration, instruction):
    """
    arg_0 arg_1 arg_2 arg_3
    Opcode: 0x2d - 0x30
    Stack: ... -> ..., []byte
    Mode: Signature
    """
    result = z3.Select(memory.args, z3.BitVecVal( int(instruction["type"].split("_")[1]), 64 ) )
    configuration.stack_push( util.Bytes(result) )
    return True

def arg_handle(configuration, instruction):
    """
    Opcode: 0x2c {uint8 arg index N}
    Stack: ... -> ..., []byte
    Nth LogicSig argument
    Mode: Signature
    """
    result = z3.Select(memory.args, z3.BitVecVal( int(instruction["params"][0]), 64 ) )
    configuration.stack_push( util.Bytes(result) )
    return True


def bit_and_handle(configuration, instruction):
    """
    Opcode: 0x1a
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A bitwise-and B
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = val2 & val1
    configuration.stack_push( util.Uint(result) )
    return True

def bit_or_handle(configuration, instruction):
    """
    Opcode: 0x1a
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A bitwise-and B
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = val2 | val1
    configuration.stack_push( util.Uint(result) )
    return True

def bit_xor_handle(configuration, instruction):
    """
    Opcode: 0x1b
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A bitwise-xor B
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = val2 ^ val1
    configuration.stack_push( util.Uint(result) )
    return True


def bit_not_handle(configuration, instruction):
    """
    Opcode: 0x1c
    Stack: ..., A: uint64 -> ..., uint64
    bitwise invert value A
    """
    val1 = configuration.stack_pop("uint")
    result = ~val1
    configuration.stack_push( util.Uint(result) )
    return True

def test_zero_handle(configuration, instruction):
    """
    Opcode: 0x14
    Stack: ..., A: uint64 -> ..., uint64
    A == 0 yields 1; else 0
    """
    val1 = configuration.stack_pop("uint")
    result = z3.If(val1 == z3.BitVecVal(0, 64), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    configuration.stack_push( util.Uint(result) )
    return True

def logic_and_handle(configuration, instruction):
    """
    Opcode: 0x10
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A is not zero and B is not zero => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If( z3.And(val2!=z3.BitVecVal(0, 64), val1!=z3.BitVecVal(0, 64)),
                             z3.BitVecVal(1, 64), z3.BitVecVal(0, 64) )
    configuration.stack_push( util.Uint(result) )
    return True


def logic_or_handle(configuration, instruction):
    """
    Opcode: 0x11
    Stack: ..., A: uint64, B: uint64 -> ..., uint64
    A is not zero or B is not zero => {0 or 1}
    """
    val1 = configuration.stack_pop("uint")
    val2 = configuration.stack_pop("uint")
    result = z3.If( z3.Or(val2!=z3.BitVecVal(0, 64), val1!=z3.BitVecVal(0, 64)),
                             z3.BitVecVal(1, 64), z3.BitVecVal(0, 64) )
    configuration.stack_push( util.Uint(result) )
    return True

def len_handle(configuration, instruction):
    """
    Opcode: 0x15
    Stack: ..., A: []byte -> ..., uint64
    yields length of byte value A
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.Int2BV(z3.Length(val1), 64)
    configuration.stack_push( util.Uint(result) )
    return True


def itob_handle(configuration, instruction): # TODO: Is there a way to better handle dynamic value?
    """
    Opcode: 0x16
    Stack: ..., A: uint64 -> ..., []byte
    converts uint64 A to big endian bytes
    """
    val1 = z3.simplify(configuration.stack_pop("uint"))
    if not z3.is_bv_value(val1):
        z3_str_val = z3.String( "itob({})".format(val1.__str__()) )
        log.debug("Use symbolic itob() variable")
    else:
        try:
            # Handle uint constant
            str_val = val1.as_long().to_bytes(2, byteorder='big').decode("Latin-1")
            z3_str_val = z3.StringVal(str_val)
        except:
            # Big integer may lead to decode failure
            return False
    configuration.stack_push( util.Bytes(z3_str_val) )
    return True


def btoi_handle(configuration, instruction):
    """
    Opcode: 0x17
    Stack: ..., A: []byte -> ..., uint64
    converts bytes A as big endian to uint64
    """
    val1 = z3.simplify(configuration.stack_pop("bytes"))
    if not z3.is_string_value(val1):
        z3_int_val = z3.BitVec( "btoi({})".format(val1.__str__()), 64 )
        log.debug("Use symbolic btoi() variable")
    else:
        # Handle byte constant
        if len(val1.as_string()) == 0:
             z3_int_val = z3.BitVecVal(0, 64)
        else:
            int_val = int( val1.as_string().replace("\\u{}","\x00").encode("Latin-1").hex(), 16)
            if int_val >= 2 ** 64:
                log.info("btoi opcode overflow")
                return False
            z3_int_val = z3.BitVecVal(int(int_val), 64)
    configuration.stack_push( util.Uint(z3_int_val) )
    return True


def load_handle(configuration, instruction):
    """
    Opcode: 0x34 {uint8 position in scratch space to load from}
    Stack: ... -> ..., any
    Ith scratch space value. All scratch spaces are 0 at program start.
    """
    param0 = int(instruction["params"][0])
    if param0 >= 256:
        log.error("Invalid scratch index")
        exit(runtime.INVALID_SCRATCH_INDEX)
    result_dict = util.Undefined({
        "array": "scratch_space",
        "op1": z3.BitVecVal(param0,64),
    })
    configuration.stack_push(result_dict)
    return True


def store_handle(configuration, instruction):
    """
    Opcode: 0x35 {uint8 position in scratch space to store to}
    Stack: ..., A -> ...
    store A to the Ith scratch space
    """
    param0 = int(instruction["params"][0])
    val_dict1 = configuration.stack_pop("original")

    if param0 >= 256:
        log.error("Invalid scratch index")
        exit(runtime.INVALID_SCRATCH_INDEX)
    if val_dict1["type"] == "undefined":
        # If we do not know the variable type, simply put it to both array!
        uint_dict = util.deepcopy(val_dict1)
        bytes_dict = util.deepcopy(val_dict1)
        memory.Define( uint_dict, "uint", configuration )
        memory.Define( bytes_dict, "bytes", configuration )
        configuration.scratch_space_return_uint = z3.Store(configuration.scratch_space_return_uint, z3.BitVecVal(param0,64), uint_dict["value"])
        configuration.scratch_space_return_bytes = z3.Store(configuration.scratch_space_return_bytes, z3.BitVecVal(param0,64), bytes_dict["value"])
        log.debug("store_handle gets undefined variable")
    elif val_dict1["type"] == "uint":
        configuration.scratch_space_return_uint = z3.Store(configuration.scratch_space_return_uint, z3.BitVecVal(param0,64), val_dict1["value"])
    elif val_dict1["type"] == "bytes":
        configuration.scratch_space_return_bytes = z3.Store(configuration.scratch_space_return_bytes, z3.BitVecVal(param0,64), val_dict1["value"])
    return True


def pop_handle(configuration, instruction):
    """
    Opcode: 0x48
    Stack: ..., A -> ...
    discard A
    """
    configuration.stack_pop("original")
    return True


def sha256_handle(configuration, instruction):
    """
    Opcode: 0x01
    Stack: ..., A: []byte -> ..., []byte
    SHA256 hash of value A, yields [32]byte
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.String( "sha256({})".format(val1.__str__()) )

    # The hash value is 32 bytes
    runtime.solver.add( z3.Length(result) == 32 )
    configuration.stack_push( util.Bytes(result))
    log.info("Use symbolic hash variable")
    return True

def ed25519verify_handle(configuration, instruction):
    """
    Opcode: 0x04
    Stack: ..., A: []byte, B: []byte, C: []byte -> ..., uint64
    for (data A, signature B, pubkey C) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
    """
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")

    # Always True
    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    log.info("Function ed25519verify detected")
    return True


def keccak256_handle(configuration, instruction):
    """
    Opcode: 0x02
    Stack: ..., A: []byte -> ..., []byte
    Keccak256 hash of value A, yields [32]byte
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.String( "keccak256({})".format(val1.__str__()) )

    # The hash value is 32 bytes
    runtime.solver.add( z3.Length(result) == 32 )
    configuration.stack_push( util.Bytes(result))
    log.info("Use symbolic hash variable")
    return True

def sha512_256_handle(configuration, instruction):
    """
    Opcode: 0x03
    Stack: ..., A: []byte -> ..., []byte
    SHA512_256 hash of value A, yields [32]byte
    """
    val1 = configuration.stack_pop("bytes")
    result = z3.String( "sha512_256({})".format(val1.__str__()) )

    # The hash value is 32 bytes
    runtime.solver.add( z3.Length(result) == 32 )
    configuration.stack_push( util.Bytes(result))
    log.info("Use symbolic hash variable")
    return True



def txn_handle(configuration, instruction):
    """
    Opcode: 0x31 {uint8 transaction field index}
    Stack: ... -> ..., any
    field F of current transaction
    """
    param0 = instruction["params"][0]
    index = runtime.get_group_index(configuration)

    if param0 == "Sender":
        if setting.IS_SMART_CONTRACT:
            # Arbitrary sender address is OK in smart contract
            dict_result = util.Bytes( z3.StringVal( setting.sender_address ) )
        else:
            dict_result = util.Bytes( z3.Select(memory.gtxn_Sender, index) )
    elif param0 == "Fee":
        dict_result = util.Uint( z3.Select(memory.gtxn_Fee, index) )
    elif param0 == "FirstValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValid, index) )
    elif param0 == "FirstValidTime":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValidTime, index) )
    elif param0 == "LastValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_LastValid, index) )
    elif param0 == "Note":
        runtime.solver.add(z3.Length( z3.Select(memory.gtxn_Note, index) ) <= 1024)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Note, index) )
    elif param0 == "Lease":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Lease, index) )
    elif param0 == "Receiver":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, index) )
    elif param0 == "Amount":
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, index) )
    elif param0 == "CloseRemainderTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_CloseRemainderTo, index) )
    elif param0 == "VotePK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_VotePK, index) )
    elif param0 == "SelectionPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_SelectionPK, index) )
    elif param0 == "VoteFirst":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteFirst, index) )
    elif param0 == "VoteLast":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteLast, index) )
    elif param0 == "VoteKeyDilution":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteKeyDilution, index) )
    elif param0 == "Type":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Type, index) )
    elif param0 == "TypeEnum":
        dict_result = util.Uint( z3.Select(memory.gtxn_TypeEnum, index) )
    elif param0 == "XferAsset": # Asset ID
        dict_result = util.Uint( z3.Select(memory.gtxn_XferAsset, index) )
    elif param0 == "AssetAmount":
        dict_result = util.Uint( z3.Select(memory.gtxn_AssetAmount, index) )
    elif param0 == "AssetSender":
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, index) )
    elif param0 == "AssetReceiver":
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, index) )
    elif param0 == "AssetCloseTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetCloseTo, index) )
    elif param0 == "GroupIndex":
        runtime.solver.add(z3.BitVec("GroupIndex", 64) <= 16)
        dict_result = util.Uint( index )
    elif param0 == "TxID":
        # Arbitrary transaction ID is OK
        dict_result = util.Bytes( z3.StringVal( "HUXPAWEPYZNL2WZXNFL7AZCAFWEHUUP3R2667BFJLFA6YHFLWALA" ) )
    elif param0 == "ApplicationID":
        dict_result = util.Uint( z3.Select(memory.gtxn_ApplicationID, index) )
    elif param0 == "OnCompletion":
        dict_result = util.Uint( z3.Select(memory.gtxn_OnCompletion, index) )
    elif param0 == "NumAppArgs":
        runtime.solver.add( z3.Select(memory.gtxn_NumAppArgs, index) <= 16 )
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAppArgs, index) )
    elif param0 == "NumAccounts":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAccounts, index) )
    elif param0 == "ApprovalProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ApprovalProgram, index) )
    elif param0 == "ClearStateProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ClearStateProgram, index) )
    elif param0 == "RekeyTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_RekeyTo, index) )
    elif param0 == "ConfigAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAsset, index) )
    elif param0 == "ConfigAssetTotal":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetTotal, index) )
    elif param0 == "ConfigAssetDecimals":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDecimals, index) )
    elif param0 == "ConfigAssetDefaultFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDefaultFrozen, index) )
    elif param0 == "ConfigAssetUnitName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetUnitName, index) )
    elif param0 == "ConfigAssetName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetName, index) )
    elif param0 == "ConfigAssetURL":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetURL, index) )
    elif param0 == "ConfigAssetMetadataHash":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetMetadataHash, index) )
    elif param0 == "ConfigAssetManager":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetManager, index) )
    elif param0 == "ConfigAssetReserve":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetReserve, index) )
    elif param0 == "ConfigAssetFreeze":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetFreeze, index) )
    elif param0 == "ConfigAssetClawback":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetClawback, index) )
    elif param0 == "FreezeAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAsset, index) )
    elif param0 == "FreezeAssetAccount":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetAccount, index) )
    elif param0 == "FreezeAssetFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetFrozen, index) )
    elif param0 == "NumAssets":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAssets, index) )
    elif param0 == "NumApplications":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumApplications, index) )
    elif param0 == "GlobalNumUint":
        dict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumUint, index) )
    elif param0 == "GlobalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumByteSlice, index) )
    elif param0 == "LocalNumUint":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumUint, index) )
    elif param0 == "LocalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumByteSlice, index) )
    elif param0 == "ExtraProgramPages":
        runtime.solver.add(z3.Select(memory.gtxn_ExtraProgramPages, index) <= 3)
        dict_result = util.Uint( z3.Select(memory.gtxn_ExtraProgramPages, index) )
    elif param0 == "Nonparticipation":
        dict_result = util.Uint( z3.Select(memory.gtxn_Nonparticipation, index) )
    elif param0 == "Logs":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Logs, index) )
    elif param0 == "NumLogs":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumLogs, index) )
    elif param0 == "CreatedAssetID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedAssetID, index) )
    elif param0 == "CreatedApplicationID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedApplicationID, index) )
    elif param0 == "LastLog":
        dict_result = util.Bytes( z3.Select(memory.gtxn_LastLog, index) )
    elif param0 == "StateProofPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_StateProofPK, index) )
    elif param0 == "NumApprovalProgramPages":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumApprovalProgramPages, index) )
    elif param0 == "NumClearStateProgramPages":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumClearStateProgramPages, index) )
    else:
        log.error("unrecognised opcode: <txn {}>".format(param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


def gtxn_handle(configuration, instruction):
    """
    Opcode: 0x33 {uint8 transaction group index} {uint8 transaction field index}
    Stack: ... -> ..., any
    field F of the Tth transaction in the current group
    """
    param0 = z3.BitVecVal( int(instruction["params"][0]), 64 )
    param1 = instruction["params"][1]
    configuration.opcode_record["gtxn_index"].append( param0 )
    
    if param1 == "Sender":
        if setting.IS_SMART_CONTRACT:
            # Arbitrary sender address is OK in smart contract
            dict_result = util.Bytes( z3.StringVal( setting.sender_address ) )
        else:
            dict_result = util.Bytes( z3.Select(memory.gtxn_Sender, param0) )
    elif param1 == "Fee":
        dict_result = util.Uint( z3.Select(memory.gtxn_Fee, param0) )
    elif param1 == "FirstValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValid, param0) )
    elif param1 == "FirstValidTime":
        dict_result = util.Uint( z3.Select(memory.gtxn_FirstValidTime, param0) )
    elif param1 == "LastValid":
        dict_result = util.Uint( z3.Select(memory.gtxn_LastValid, param0) )
    elif param1 == "Note":
        runtime.solver.add(z3.Length( z3.Select(memory.gtxn_Note, param0) ) <= 1024)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Note, param0) )
    elif param1 == "Lease":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Lease, param0) )
    elif param1 == "Receiver":
        configuration.opcode_record["gtxn_pay_index"].append( param0 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, param0) )
    elif param1 == "Amount":
        configuration.opcode_record["gtxn_pay_index"].append( param0 )
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, param0) )
    elif param1 == "CloseRemainderTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_CloseRemainderTo, param0) )
    elif param1 == "VotePK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_VotePK, param0) )
    elif param1 == "SelectionPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_SelectionPK, param0) )
    elif param1 == "VoteFirst":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteFirst, param0) )
    elif param1 == "VoteLast":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteLast, param0) )
    elif param1 == "VoteKeyDilution":
        dict_result = util.Uint( z3.Select(memory.gtxn_VoteKeyDilution, param0) )
    elif param1 == "Type":
        configuration.opcode_record["gtxn_pay_index"].append( param0 )
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_Type, param0) )
    elif param1 == "TypeEnum":
        configuration.opcode_record["gtxn_pay_index"].append( param0 )
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Uint( z3.Select(memory.gtxn_TypeEnum, param0) )
    elif param1 == "XferAsset":
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Uint( z3.Select(memory.gtxn_XferAsset, param0) )
    elif param1 == "AssetAmount":
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Uint( z3.Select(memory.gtxn_AssetAmount, param0) )
    elif param1 == "AssetSender":
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, param0) )
    elif param1 == "AssetReceiver":
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, param0) )
    elif param1 == "AssetCloseTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetCloseTo, param0) )
    elif param1 == "GroupIndex":
        dict_result = util.Uint( param0 )
    elif param1 == "TxID":
        # Arbitrary transaction ID is OK
        dict_result = util.Bytes( z3.StringVal( "HUXPAWEPYZNL2WZXNFL7AZCAFWEHUUP3R2667BFJLFA6YHFLWALA" ) )
    elif param1 == "ApplicationID":
        if runtime.app_call_group_index != -1 and configuration.app_area == False:
            runtime.path_include_app = 1
        dict_result = util.Uint( z3.Select(memory.gtxn_ApplicationID, param0) )
    elif param1 == "OnCompletion":
        dict_result = util.Uint( z3.Select(memory.gtxn_OnCompletion, param0) )
    elif param1 == "NumAppArgs":
        runtime.solver.add( z3.Select(memory.gtxn_NumAppArgs, param0) <= 16 )
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAppArgs, param0) )
    elif param1 == "NumAccounts":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAccounts, param0) )
    elif param1 == "ApprovalProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ApprovalProgram, param0) )
    elif param1 == "ClearStateProgram":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ClearStateProgram, param0) )
    elif param1 == "RekeyTo":
        dict_result = util.Bytes( z3.Select(memory.gtxn_RekeyTo, param0) )
    elif param1 == "ConfigAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAsset, param0) )
    elif param1 == "ConfigAssetTotal":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetTotal, param0) )
    elif param1 == "ConfigAssetDecimals":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDecimals, param0) )
    elif param1 == "ConfigAssetDefaultFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_ConfigAssetDefaultFrozen, param0) )
    elif param1 == "ConfigAssetUnitName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetUnitName, param0) )
    elif param1 == "ConfigAssetName":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetName, param0) )
    elif param1 == "ConfigAssetURL":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetURL, param0) )
    elif param1 == "ConfigAssetMetadataHash":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetMetadataHash, param0) )
    elif param1 == "ConfigAssetManager":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetManager, param0) )
    elif param1 == "ConfigAssetReserve":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetReserve, param0) )
    elif param1 == "ConfigAssetFreeze":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetFreeze, param0) )
    elif param1 == "ConfigAssetClawback":
        dict_result = util.Bytes( z3.Select(memory.gtxn_ConfigAssetClawback, param0) )
    elif param1 == "FreezeAsset":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAsset, param0) )
    elif param1 == "FreezeAssetAccount":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetAccount, param0) )
    elif param1 == "FreezeAssetFrozen":
        dict_result = util.Uint( z3.Select(memory.gtxn_FreezeAssetFrozen, param0) )
    elif param1 == "NumAssets":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumAssets, param0) )
    elif param1 == "NumApplications":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumApplications, param0) )
    elif param1 == "GlobalNumUint":
        pasdict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumUint, param0) )
    elif param1 == "GlobalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_GlobalNumByteSlice, param0) )
    elif param1 == "LocalNumUint":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumUint, param0) )
    elif param1 == "LocalNumByteSlice":
        dict_result = util.Uint( z3.Select(memory.gtxn_LocalNumByteSlice, param0) )
    elif param1 == "ExtraProgramPages":
        dict_result = util.Uint( z3.Select(memory.gtxn_ExtraProgramPages, param0) )
    elif param1 == "Nonparticipation":
        dict_result = util.Uint( z3.Select(memory.gtxn_Nonparticipation, param0) )
    elif param1 == "Logs":
        dict_result = util.Bytes( z3.Select(memory.gtxn_Logs, param0) )
    elif param1 == "NumLogs":
        dict_result = util.Uint( z3.Select(memory.gtxn_NumLogs, param0) )
    elif param1 == "CreatedAssetID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedAssetID, param0) )
    elif param1 == "CreatedApplicationID":
        dict_result = util.Uint( z3.Select(memory.gtxn_CreatedApplicationID, param0) )
    elif param1 == "LastLog":
        dict_result = util.Bytes( z3.Select(memory.gtxn_LastLog, param0) )
    elif param1 == "StateProofPK":
        dict_result = util.Bytes( z3.Select(memory.gtxn_StateProofPK, param0) )
    else:
        log.error("unrecognised opcode: <gtxn {} {}>".format(param0, param1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True



def global_handle(configuration, instruction):
    """
    Opcode: 0x32 {uint8 global field index}
    Stack: ... -> ..., any
    global field F
    """
    param0 = instruction["params"][0]
    if param0 == "MinTxnFee":
        runtime.solver.add(z3.BitVec("global_MinTxnFee", 64) >= 1000)
        dict_result = util.Uint( z3.BitVec("global_MinTxnFee", 64) )
    elif param0 == "MinBalance":
        runtime.solver.add(z3.BitVec("global_MinBalance", 64) >= 100000)
        dict_result = util.Uint( z3.BitVec("global_MinBalance", 64) )
    elif param0 == "MaxTxnLife":
        dict_result = util.Uint( z3.BitVecVal(1000, 64) )
    elif param0 == "ZeroAddress":
        dict_result = util.Bytes( z3.StringVal( "\x00" * 32 ) )
    elif param0 == "GroupSize":
        runtime.solver.add(z3.BitVec("global_GroupSize", 64) >= 1)
        dict_result = util.Uint( z3.BitVec("global_GroupSize", 64) )
    elif param0 == "LogicSigVersion":
        dict_result = util.Uint( z3.BitVec("global_LogicSigVersion", 64) )
    elif param0 == "Round":
        dict_result = util.Uint( z3.BitVec("global_Round", 64) )
    elif param0 == "LatestTimestamp":
        configuration.opcode_record["timestamp"] = True
        dict_result = util.Uint( z3.BitVec("global_LatestTimestamp", 64) )
    elif param0 == "CurrentApplicationID":
        dict_result = util.Uint( z3.BitVec("global_CurrentApplicationID", 64) )
    elif param0 == "CreatorAddress":
        # An arbitrary address but different from sender address
        dict_result = util.Bytes( z3.StringVal( "\x01" * 32 ) )
    elif param0 == "CurrentApplicationAddress":
        # An arbitrary address but different from creator address
        dict_result = util.Bytes( z3.StringVal( "\x02" * 32 ) )
    elif param0 == "GroupID":
        dict_result = util.Bytes( z3.String("global_GroupID") )
    elif param0 == "OpcodeBudget":
        dict_result = util.Uint( z3.BitVecVal(setting.MAXIMUM_COST - configuration.total_cost, 64) )
    elif param0 == "CallerApplicationID":
        dict_result = util.Uint( z3.BitVec("global_CallerApplicationID", 64) )
    elif param0 == "CallerApplicationAddress":
        dict_result = util.Bytes( z3.String("global_CallerApplicationAddress") )
    else:
        log.error("unrecognised opcode: <global {}>".format(param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


# This implementation is deprecated because z3.BV2Int() is inefficient
def mulw_handle_deprecated(configuration, instruction):
    """
    Opcode: 0x1d
    Stack: ..., A: uint64, B: uint64 -> ..., X: uint64, Y: uint64
    A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    runtime.solver.add( z3.BV2Int(valA) * z3.BV2Int(valB) <= 2 ** 128 - 1 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("mulw opcode overflow")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (mulw_handle)")
        return False
    
    result = z3.Int2BV(z3.BV2Int(valA) * z3.BV2Int(valB), 128)
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True


def mulw_handle(configuration, instruction):
    """
    Opcode: 0x1d
    Stack: ..., A: uint64, B: uint64 -> ..., X: uint64, Y: uint64
    A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low
    """    
    valB = configuration.stack_pop("uint")
    valA = configuration.stack_pop("uint")

    valB = z3.Concat(z3.BitVecVal(0, 64), valB)
    valA = z3.Concat(z3.BitVecVal(0, 64), valA)

    runtime.solver.add( z3.BVMulNoOverflow(valA, valB, False) )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Integer multiplication overflow detected")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (mulw_handle)")
        return False
    
    result = valA * valB    
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True


def err_handle(configuration, instruction):
    """
    Opcode: 0x00
    Stack: ... -> ...
    Fail immediately.
    """
    return False