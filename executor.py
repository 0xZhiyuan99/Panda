import z3
import runtime
import logging
import setting
import opcodes
import memory
import util
import math
import analyzer
import re
import base64
import algosdk
from basic_class import ConfigurationError

log = logging.getLogger(__name__)

def trace(configuration, instruction):
    if setting.DEBUG_MODE == True:
        print("{} {} execute: {}".format(configuration.current_block_depth, len(configuration.stack), instruction))
        #print(len(runtime.block_search_record))
        #print(runtime.solver.get_constraints())
        #debug_display_stack(configuration, instruction)
        print("==============================")
    return

def cond_jump_to_block(configuration, target, cond):
    runtime.solver.push()
    runtime.solver.add( cond )
    flag = runtime.solver.check()
    if flag == z3.sat:
        new_configuration = configuration.copy()
        new_configuration.current_block_address = target
        symbolic_execute_block(new_configuration)

        # Set the end address of the current block as PC 
        runtime.pc = runtime.vertices[configuration.current_block_address].end_address
    else:
        if flag == z3.unknown:
            log.info("Z3 timeout (cond_jump_to_block)")

        # Reach end block
        runtime.leaves_number += 1
    runtime.solver.pop()

def jump_to_block(configuration, target):
    runtime.solver.push()
    new_configuration = configuration.copy()
    new_configuration.current_block_address = target
    symbolic_execute_block(new_configuration)

    # Set the end address of the current block as PC 
    runtime.pc = runtime.vertices[configuration.current_block_address].end_address

    runtime.solver.pop()

def leave_block(current_block, internal=False):
    if internal == False:
        runtime.leaves_number += 1
    runtime.block_search_record.pop()
    current_block.access_count -= 1

def show_backtrace():
    for pair in runtime.block_search_record:
        print(runtime.instructions[pair[0]]["line_number"], "-", runtime.instructions[pair[1]]["line_number"])
    exit()

def symbolic_execute_block(configuration):
    
    current_block = runtime.vertices[configuration.current_block_address]
    runtime.block_search_record.append( (current_block.start_address, current_block.end_address) )
    current_block.access_count += 1
    configuration.current_block_depth += 1

    if configuration.current_block_depth > setting.BLOCK_SEARCH_DEPTH:
        log.info("Reach maximum block depth")
        leave_block(current_block)
        return
    if current_block.access_count > setting.BLOCK_ACCESS_COUNT:
        log.info("Reach maximum block access count")
        leave_block(current_block)
        return  
    
    
    for address in range(current_block.start_address, current_block.end_address):
        runtime.pc = address

        # Execute each instruction in the current block
        if not symbolic_execute_instruction(configuration, current_block.insturctions[address]):
            # Reach end block
            leave_block(current_block)
            return

    # Handle the end instruction
    try:
        runtime.pc = current_block.end_address
        end_instruction = current_block.insturctions[current_block.end_address]
        configuration.total_cost += opcodes.get_cost(end_instruction["type"])

        if(configuration.total_cost > setting.MAXIMUM_COST):
            log.info("Reach maximum cost")
            leave_block(current_block)
            return
        
        if end_instruction["type"] == "bz":
            trace(configuration, end_instruction)
            target = int(end_instruction["params"][0])
            flag = configuration.stack_pop("uint")
            cond = (flag == 0)
            cond_jump_to_block(configuration, target, cond)
            if current_block.adjacent_block_address != -1:
                cond_jump_to_block(configuration, current_block.adjacent_block_address, z3.Not(cond))
        
        elif end_instruction["type"] == "bnz":
            trace(configuration, end_instruction)
            if end_instruction["dest_label"] == "app_label":
                if runtime.path_include_app == 0:
                    return_handle(configuration, None)
                    # Reach end block
                    leave_block(current_block)
                    return
                else:
                    configuration.app_area = True
            
            target = int(end_instruction["params"][0])
            flag = configuration.stack_pop("uint")
            cond = (flag != 0)
            cond_jump_to_block(configuration, target, cond)
            if current_block.adjacent_block_address != -1:
                cond_jump_to_block(configuration, current_block.adjacent_block_address, z3.Not(cond))

        elif end_instruction["type"] == "b":
            trace(configuration, end_instruction)
            target = int(end_instruction["params"][0])
            jump_to_block(configuration, target)
        
        elif end_instruction["type"] == "callsub":
            trace(configuration, end_instruction)

            # Store the function return address
            configuration.call_stack_push(current_block.adjacent_block_address)

            target = int(end_instruction["params"][0])
            jump_to_block(configuration, target)
        
        elif end_instruction["type"] == "retsub":
            trace(configuration, end_instruction)
            target = configuration.call_stack_pop()
            jump_to_block(configuration, target)
        
        # The end instruction is not a jump type instruction
        else:
            configuration.total_cost -= opcodes.get_cost(end_instruction["type"])

            if not symbolic_execute_instruction(configuration, end_instruction):
                # Reach end block
                leave_block(current_block)
                return
            
            if current_block.adjacent_block_address != -1:
                jump_to_block(configuration, current_block.adjacent_block_address)
            else:
                # Add a return instruction explicitly if there is no return instruction at the end of the program
                return_handle(configuration, None)
            
                # Reach end block
                leave_block(current_block)
                return
        
        leave_block(current_block, internal=True)
        return
        
    except ConfigurationError:
        leave_block(current_block)
        return


def symbolic_execute_instruction(configuration, instruction):
    trace(configuration, instruction)
    if instruction["type"] in ["bnz", "bz", "b", "callsub", "retsub"]:
        log.critical("Find a jump instruction inside the basic block!")
        exit(runtime.EXECUTE_FAILED)
    
    configuration.total_cost += opcodes.get_cost(instruction["type"])
    if(configuration.total_cost > setting.MAXIMUM_COST):
        log.info("Reach maximum cost")
        return False
    
    # Run opcode's handle
    handle = opcodes.get_handle(instruction["type"])
    if handle != None:
        try:
            return handle(configuration, instruction)
        except ConfigurationError:
            return False
    else:
        log.info("Unsupport opcode detected ({})".format(instruction["type"]))
        return False

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
    configuration.stack_push( util.Bytes(result) )
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
            if int_val > 2 ** 64 - 1:
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

def loads_handle(configuration, instruction):
    """
    Opcode: 0x3e
    Stack: ..., A: uint64 → ..., any
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

def stores_handle(configuration, instruction):
    """
    Opcode: 0x3f
    Stack: ..., A: uint64, B → ...
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

def pop_handle(configuration, instruction):
    """
    Opcode: 0x48
    Stack: ..., A -> ...
    discard A
    """
    configuration.stack_pop("original")
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
        log.error("Invalid cover parameter")
        exit(runtime.INVALID_COVER_PARAM)
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

def err_handle(configuration, instruction):
    """
    Opcode: 0x00
    Stack: ... -> ...
    Fail immediately.
    """
    return False

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
    runtime.solver.add( end < z3.Length(val1) )

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
    runtime.solver.add( z3.BV2Int(end) < z3.Length(str_val) )
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
    Stack: ..., A: []byte, B: []byte, C: []byte → ..., uint64
    for (data A, signature B, pubkey C) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
    """
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")

    # Always True
    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    log.info("Function ed25519verify detected")
    return True


def ecdsa_verify_handle(configuration, instruction):
    """
    Opcode: 0x05 {uint8 curve index}
    Stack: ..., A: []byte, B: []byte, C: []byte, D: []byte, E: []byte → ..., uint64
    for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}
    Availability: v5
    """
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    configuration.stack_pop("bytes")
    
    # Always True
    configuration.stack_push( util.Uint( z3.BitVecVal(1,64) ))
    log.info("Function ecdsa_verify detected")
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
    if runtime.app_call_group_index != -1:
        if configuration.app_area == False:
            index = z3.BitVec("GroupIndex", 64)
        else:
            index = z3.BitVecVal(runtime.app_call_group_index, 64)
    else:
        index = z3.BitVec("GroupIndex", 64)

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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_Receiver, index)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, index) )
    elif param0 == "Amount":
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, index) )
    elif param0 == "CloseRemainderTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_CloseRemainderTo, index)) == 32)
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetSender, index)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, index) )
    elif param0 == "AssetReceiver":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetReceiver, index)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, index) )
    elif param0 == "AssetCloseTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetCloseTo, index)) == 32)
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
    else:
        log.error("unrecognised opcode: <txn {}>".format(param0))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
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

    if runtime.app_call_group_index != -1:
        if configuration.app_area == False:
            index = z3.BitVec("GroupIndex", 64)
        else:
            index = z3.BitVecVal(runtime.app_call_group_index, 64)
    else:
        index = z3.BitVec("GroupIndex", 64)

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, index, param1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, index, param1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, index, param1) )
    elif param0 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, index, param1) )
    else:
        log.error("unrecognised opcode: <txna {} {}>".format(param0, param1))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
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

    if runtime.app_call_group_index != -1:
        if configuration.app_area == False:
            index = z3.BitVec("GroupIndex", 64)
        else:
            index = z3.BitVecVal(runtime.app_call_group_index, 64)
    else:
        index = z3.BitVec("GroupIndex", 64)

    if param0 == "ApplicationArgs":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_ApplicationArgs, index, val1) )
    elif param0 == "Applications":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Applications, index, val1) )
    elif param0 == "Assets":
        dict_result = util.Uint( memory.select_2D_array(memory.gtxna_Assets, index, val1) )
    elif param0 == "Accounts":
        dict_result = util.Bytes( memory.select_2D_array(memory.gtxna_Accounts, index, val1) )
    else:
        log.error("unrecognised opcode: <txnas {} {}>".format(param0, val1))
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_Receiver, param0)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, param0) )
    elif param1 == "Amount":
        configuration.opcode_record["gtxn_pay_index"].append( param0 )
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, param0) )
    elif param1 == "CloseRemainderTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_CloseRemainderTo, param0)) == 32)
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetSender, param0)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, param0) )
    elif param1 == "AssetReceiver":
        configuration.opcode_record["gtxn_axfer_index"].append( param0 )
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetReceiver, param0)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, param0) )
    elif param1 == "AssetCloseTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetCloseTo, param0)) == 32)
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_RekeyTo, param0)) == 32)
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
    else:
        log.error("unrecognised opcode: <gtxna {} {} {}>".format(param0, param1, param2))
        exit(runtime.UNRECOGNISED_OPCODE)
    
    configuration.stack_push(dict_result)
    return True


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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_Receiver, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_Receiver, val1) )
    elif param0 == "Amount":
        configuration.opcode_record["gtxn_pay_index"].append( val1 )
        dict_result = util.Uint( z3.Select(memory.gtxn_Amount, val1) )
    elif param0 == "CloseRemainderTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_CloseRemainderTo, val1)) == 32)
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetSender, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetSender, val1) )
    elif param0 == "AssetReceiver":
        configuration.opcode_record["gtxn_axfer_index"].append( val1 )
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetReceiver, val1)) == 32)
        dict_result = util.Bytes( z3.Select(memory.gtxn_AssetReceiver, val1) )
    elif param0 == "AssetCloseTo":
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_AssetCloseTo, val1)) == 32)
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
        runtime.solver.add(z3.Length(z3.Select(memory.gtxn_RekeyTo, val1)) == 32)
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
    else:
        log.error("unrecognised opcode: <gtxnsa {} {} {}>".format(val1, param0, param1))
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
    else:
        log.error("unrecognised opcode: <gtxnsas {} {} {}>".format(val2, param0, val1))
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
        runtime.solver.add(z3.BitVec("global_GroupSize", 64) <= 16)
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
    result = z3.StringVal( bytes.fromhex(param0[2:]).decode("Latin-1") )
    configuration.stack_push( util.Bytes(result) )
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

def int_handle(configuration, instruction):
    # Similar to pushint
    param0 = int(instruction["params"][0])
    result = z3.BitVecVal(param0, 64)
    configuration.stack_push( util.Uint(result) )
    return True


def byte_handle(configuration, instruction):
    param0 = instruction["params"][0]
    string_match = re.match("\"(.*)\"", param0)
    base64_match = re.match("base64\((.*)\)", param0)

    if string_match != None:
        result = z3.StringVal( string_match.group(1) )
    elif base64_match != None:
        result = z3.StringVal( base64.b64decode( base64_match.group(1) ).decode("Latin-1") )
    else:
        log.error("Unrecognised data format in 'byte' opcode")
        exit(setting.UNRECOGNISED_DATA_FORMAT)

    configuration.stack_push( util.Bytes(result) )
    return True

def addr_handle(configuration, instruction):
    param0 = instruction["params"][0]
    result = z3.StringVal( algosdk.encoding.decode_address(param0).decode("Latin-1") )
    configuration.stack_push( util.Bytes(result) )
    return True

def itxn_begin_handle(configuration, instruction):
    """
    Opcode: 0xb1
    Stack: ... -> ...
    begin preparation of a new inner transaction in a new transaction group
    Availability: v5
    Mode: Application
    """
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
    runtime.itxn_field[param0] = val

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


def app_local_get_handle(configuration, instruction):
    """
    Opcode: 0x62
    Stack: ..., A, B: []byte -> ..., any
    local state of the key B in the current application in account A
    Availability: v2
    Mode: Application
    """
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
    Stack: ..., A: uint64, B: []byte → ..., X: any, Y: uint64
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
    Stack: ..., A, B: uint64, C: []byte → ..., X: any, Y: uint64
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

def app_params_get_handle(configuration, instruction):
    """
    Opcode: 0x72 {uint8 app params field index}
    Stack: ..., A: uint64 -> ..., X: any, Y: uint64
    X is field F from app A. Y is 1 if A exists, else 0
    Availability: v5
    Mode: Application
    """
    param0 = instruction["params"][0]
    val1 = configuration.stack_pop("original")
    if val1["type"] == "undefined":
        log.info("app_params_get_handle gets undefined variable")
        return False
    elif val1["type"] == "uint":
        if param0 == "AppGlobalNumUint":
            dict_result = util.Uint( z3.Select(memory.AppGlobalNumUint_uint, val1["value"]) )
        elif param0 == "AppGlobalNumByteSlice":
            dict_result = util.Uint( z3.Select(memory.AppGlobalNumByteSlice_uint, val1["value"]) )
        elif param0 == "AppLocalNumUint":
            dict_result = util.Uint( z3.Select(memory.AppLocalNumUint_uint, val1["value"]) )
        elif param0 == "AppLocalNumByteSlice":
            dict_result = util.Uint( z3.Select(memory.AppLocalNumByteSlice_uint, val1["value"]) )
        elif param0 == "AppExtraProgramPages":
            runtime.solver.add(z3.Select(memory.AppExtraProgramPages_uint, val1["value"]) <= 3)
            dict_result = util.Uint( z3.Select(memory.AppExtraProgramPages_uint, val1["value"]) )
        elif param0 == "AppApprovalProgram":
            dict_result = util.Bytes( z3.Select(memory.AppApprovalProgram_uint, val1["value"]) )
        elif param0 == "AppClearStateProgram":
            dict_result = util.Bytes( z3.Select(memory.AppClearStateProgram_uint, val1["value"]) )
        elif param0 == "AppCreator":
            dict_result = util.Bytes( z3.StringVal( "\x01" * 32 ) )
        elif param0 == "AppAddress":
            runtime.solver.add(z3.Length(z3.Select(memory.AppAddress_uint, val1["value"])) == 32)
            dict_result = util.Bytes( z3.Select(memory.AppAddress_uint, val1["value"]) )
    elif val1["type"] == "bytes":
        if param0 == "AppGlobalNumUint":
            dict_result = util.Uint( z3.Select(memory.AppGlobalNumUint_bytes, val1["value"]) )
        elif param0 == "AppGlobalNumByteSlice":
            dict_result = util.Uint( z3.Select(memory.AppGlobalNumByteSlice_bytes, val1["value"]) )
        elif param0 == "AppLocalNumUint":
            dict_result = util.Uint( z3.Select(memory.AppLocalNumUint_bytes, val1["value"]) )
        elif param0 == "AppLocalNumByteSlice":
            dict_result = util.Uint( z3.Select(memory.AppLocalNumByteSlice_bytes, val1["value"]) )
        elif param0 == "AppExtraProgramPages":
            runtime.solver.add(z3.Select(memory.AppExtraProgramPages_bytes, val1["value"]) <= 3)
            dict_result = util.Uint( z3.Select(memory.AppExtraProgramPages_bytes, val1["value"]) )
        elif param0 == "AppApprovalProgram":
            dict_result = util.Bytes( z3.Select(memory.AppApprovalProgram_bytes, val1["value"]) )
        elif param0 == "AppClearStateProgram":
            dict_result = util.Bytes( z3.Select(memory.AppClearStateProgram_bytes, val1["value"]) )
        elif param0 == "AppCreator":
            dict_result = util.Bytes( z3.StringVal( "\x01" * 32 ) )
        elif param0 == "AppAddress":
            runtime.solver.add(z3.Length(z3.Select(memory.AppAddress_bytes, val1["value"])) == 32)
            dict_result = util.Bytes( z3.Select(memory.AppAddress_bytes, val1["value"]) )

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
    Stack: ..., A: []byte, B: uint64, C: uint64 → ..., []byte
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

def app_opted_in_handle(configuration, instruction):
    """
    Opcode: 0x61
    Stack: ..., A, B: uint64 -> ..., uint64
    1 if account A is opted in to application B, else 0
    Availability: v2
    Mode: Application
    """
    configuration.stack_pop("original")
    configuration.stack_pop("original")
    result = z3.BitVecVal( 1, 64 )
    configuration.stack_push( util.Uint(result) )
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

def app_global_del_handle(configuration, instruction):
    """
    Opcode: 0x69
    Stack: ..., A: []byte → ...
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
    Stack: ..., A, B: []byte → ...
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



def ecdsa_pk_decompress_handle(configuration, instruction):
    """
    Opcode: 0x06 {uint8 curve index}
    Stack: ..., A: []byte → ..., X: []byte, Y: []byte
    decompress pubkey A into components X, Y
    Availability: v5
    """    
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
    Stack: ..., A: []byte, B: uint64, C: []byte, D: []byte → ..., X: []byte, Y: []byte
    for (data A, recovery id B, signature C, D) recover a public key
    Cost: 2000
    Availability: v5
    """    
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


def mulw_handle(configuration, instruction):
    """
    Opcode: 0x1d
    Stack: ..., A: uint64, B: uint64 → ..., X: uint64, Y: uint64
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


def addw_handle(configuration, instruction):
    """
    Opcode: 0x1e
    Stack: ..., A: uint64, B: uint64 → ..., X: uint64, Y: uint64
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


def divmodw_handle(configuration, instruction):
    """
    Opcode: 0x1f
    Stack: ..., A: uint64, B: uint64, C: uint64, D: uint64 → ..., W: uint64, X: uint64, Y: uint64, Z: uint64
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
    Stack: ..., A: []byte, B: uint64, C: uint64 → ..., []byte
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

def extract_uint16_handle(configuration, instruction):
    """
    Opcode: 0x59
    Stack: ..., A: []byte, B: uint64 → ..., uint64
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

    final_result = z3.Concat(result1, result2)

    configuration.stack_push( util.Uint(final_result) )
    return True


def extract_uint32_handle(configuration, instruction):
    """
    Opcode: 0x5a
    Stack: ..., A: []byte, B: uint64 → ..., uint64
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

    final_result = z3.Concat(result1, result2, result3, result4)

    configuration.stack_push( util.Uint(final_result) )
    return True


def extract_uint64_handle(configuration, instruction):
    """
    Opcode: 0x5b
    Stack: ..., A: []byte, B: uint64 → ..., uint64
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


def expw_handle(configuration, instruction):
    """
    Opcode: 0x95
    Stack: ..., A: uint64, B: uint64 → ..., X: uint64, Y: uint64
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

    runtime.solver.add( z3.BV2Int(valA) ** z3.BV2Int(valB) <= 2 ** 128 - 1 )
    flag = runtime.solver.check()
    if flag == z3.unsat:
        log.info("Expw opcode overflow")
        return False
    elif flag == z3.unknown:
        log.info("Z3 timeout (expw_handle)")
        return False

    result = z3.Int2BV(z3.BV2Int(valA) ** z3.BV2Int(valB), 128)
    resultY = z3.Extract(63, 0, result)
    resultX = z3.Extract(127, 64, result)

    configuration.stack_push( util.Uint(resultX) )
    configuration.stack_push( util.Uint(resultY) )
    return True


def BEQ_handle(configuration, instruction):
    """
    Opcode: 0xa8
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
        result = z3.If(z3.BV2Int(bvA) <= z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b<= opcode")
        return False

def BLT_handle(configuration, instruction):
    """
    Opcode: 0xa4
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
        result = z3.If(z3.BV2Int(bvA) < z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b< opcode")
        return False


def BGE_handle(configuration, instruction):
    """
    Opcode: 0xa7
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
        result = z3.If(z3.BV2Int(bvA) >= z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b>= opcode")
        return False


def BGT_handle(configuration, instruction):
    """
    Opcode: 0xa5
    Stack: ..., A: []byte, B: []byte → ..., uint64
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
        result = z3.If(z3.BV2Int(bvA) > z3.BV2Int(bvB), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
        configuration.stack_push( util.Uint(result) )
        return True
    else:
        log.info("Symbolic operand in b> opcode")
        return False


def Brem_handle(configuration, instruction):
    """
    Opcode: 0xaa
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte, B: []byte → ..., []byte
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
    Stack: ..., A: []byte → ..., []byte
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


def getbit_handle(configuration, instruction):
    """
    Opcode: 0x53
    Stack: ..., A, B: uint64 → ..., uint64
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
        result = z3.simplify(z3.If( (targetBV & (1 << remainder)) > 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)))
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
    Stack: ..., A, B: uint64, C: uint64 → ..., any
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



def bitlen_handle(configuration, instruction):
    """
    Opcode: 0x93
    Stack: ..., A → ..., uint64
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


def select_handle(configuration, instruction):
    """
    Opcode: 0x4d
    Stack: ..., A, B, C: uint64 → ..., A or B
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
    configuration.stack_push( util.Uint(result) )
    return True


def itxn_handle(configuration, instruction):
    """
    Opcode: 0xb4 {uint8 transaction field index}
    Stack: ... → ..., any
    field F of the last inner transaction
    Availability: v5
    Mode: Application
    """

    param0 = instruction["params"][0]

    if param0 not in runtime.itxn_field:
        log.info("Invalid itxn opcode")
        return False

    configuration.stack_push( runtime.itxn_field[param0] )
    return True


def itxna_handle(configuration, instruction):
    """
    Opcode: 0xb5 {uint8 transaction field index} {uint8 transaction field array index}
    Stack: ... → ..., any
    Ith value of the array field F of the last inner transaction
    Availability: v5
    Mode: Application
    """

    param0 = instruction["params"][0]

    if param0 not in runtime.itxn_field:
        log.info("Invalid itxna opcode")
        return False

    configuration.stack_push( runtime.itxn_field[param0] )
    return True


def internel_jump(configuration, instruction):
    log.critical("Internal jump instruction detected")
    exit(runtime.INTERNAL_JUMP_INSTRUCTION)

def debug_display_stack(configuration, instruction):
    for index in range(len(configuration.stack)):
        stack_val = configuration.stack[index]
        print(index, stack_val)
    return True

def debug_display_global_state(configuration, instruction):
    print(configuration.global_state)
    return True

def debug_exit(configuration, instruction):
    runtime.solver.check()
    #print(runtime.solver.model())
    exit()

