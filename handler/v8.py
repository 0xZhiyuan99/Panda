import logging

log = logging.getLogger(__name__)

def bury_handle(configuration, instruction):
    """
    Opcode: 0x45 {uint8 depth}
    Stack: ..., A → ...
    Replace the Nth value from the top of the stack. bury 0 fails.
    Availability: v8
    """

    param0 = int(instruction["params"][0])
    val_dict1 = configuration.stack_pop("original")
    if param0 == 0:
        return False
    elif param0 > len(configuration.stack):
        log.info("Invalid stack operation in 'bury' opcode")
        return False
    configuration.stack[-param0] = val_dict1
    return True

def frame_dig_handle(configuration, instruction):
    """
    Opcode: 0x8b {int8 frame slot}
    Stack: ... → ..., any
    Nth (signed) value from the frame pointer.
    Availability: v8
    """

    if len(configuration.call_stack) == 0:
        log.info("frame_dig with empty callstack")
        return False

    param0 = int(instruction["params"][0])
    index = param0 + configuration.frame_stack[-1]

    if index >= len(configuration.stack):
        log.info("Invalid stack operation in 'frame_dig' opcode")
        return False

    configuration.stack_push( configuration.stack[index] )
    return True

def frame_bury_handle(configuration, instruction):
    """
    Opcode: 0x8c {int8 frame slot}
    Stack: ..., A → ...
    Replace the Nth (signed) value from the frame pointer in the stack
    Availability: v8
    """

    if len(configuration.call_stack) == 0:
        log.info("frame_bury with empty callstack")
        return False

    param0 = int(instruction["params"][0])
    index = param0 + configuration.frame_stack[-1]
    val_dict1 = configuration.stack_pop("original")

    if index >= len(configuration.stack):
        log.info("Invalid stack operation in 'frame_bury' opcode")
        return False

    configuration.stack[index] = val_dict1
    return True


def proto_handle(configuration, instruction):
    """
    Opcode: 0x8a {uint8 arguments} {uint8 return values}
    Stack: ... → ...
    Prepare top call frame for a retsub that will assume A args and R return values.
    Availability: v8
    """

    args = int(instruction["params"][0])
    returns = int(instruction["params"][1])

    if len(configuration.stack) < args:
        log.info("callsub to proto that requires {} args with stack height {}".format(args, len(configuration.stack)))
        return False
    if len(configuration.proto_arg) >= len(configuration.call_stack):
        log.info("Invalid proto opcode")
        return False

    configuration.proto_arg.append(args)
    configuration.proto_return.append(returns)

    return True


def popn_handle(configuration, instruction):
    """
    Opcode: 0x46 {uint8 stack depth}
    Stack: ..., [N items] → ...
    Remove N values from the top of the stack
    Availability: v8
    """
    param0 = int(instruction["params"][0])
    for i in range(param0):
        configuration.stack_pop("original")
    return True

def dupn_handle(configuration, instruction):
    """
    Opcode: 0x47 {uint8 copy count}
    Stack: ..., A → ..., A, [N copies of A]
    duplicate A, N times
    Availability: v8
    """
    param0 = int(instruction["params"][0])

    # Note that the duplicate value is a reference of the original value
    val1 = configuration.stack_get(-1)
    for i in range(param0):
        configuration.stack_push(val1)
    return True