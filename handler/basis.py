import logging
import runtime
import util
import z3
import algosdk

log = logging.getLogger(__name__)

def int_handle(configuration, instruction):
    # Similar to pushint
    param0 = instruction["params"][0]
    if param0.startswith("0x"):
        param0 = int(param0[2:],16)
    else:
        param0 = int(param0)
    if int(param0) >= 2 ** 64:
        log.error("Invalid int opcode")
        exit(runtime.INVALID_INTCBLOCK)
    result = z3.BitVecVal(param0, 64)
    configuration.stack_push( util.Uint(result) )
    return True


def addr_handle(configuration, instruction):
    param0 = instruction["params"][0]
    result = z3.StringVal( algosdk.encoding.decode_address(param0).decode("Latin-1") )
    configuration.stack_push( util.Bytes(result) )
    return True


def internel_jump(configuration, instruction):
    log.critical("Internal jump instruction detected")
    exit(runtime.INTERNAL_JUMP_INSTRUCTION)
