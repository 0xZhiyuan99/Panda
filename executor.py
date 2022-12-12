import z3
import runtime
import logging
import setting
import opcodes
import handler.v2
import memory
from basic_class import ConfigurationError

show_clear_state_message = False

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


def clear_state_constraint(configuration):
    if runtime.app_call_group_index == -1:
        return False

    index = runtime.get_group_index(configuration)
    new_constraints = []
    new_constraints.append( z3.Select(memory.gtxn_OnCompletion, index) == 3 ) # ClearState
    flag = runtime.solver.satisfy(new_constraints)
    if flag == z3.sat:
        return True
    else:
        return False


def symbolic_execute_block(configuration):
    global show_clear_state_message
    
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

            # If the current execution path doesn't contain a call to a validator
            # then stop execution immediately rather than jump to the code in the validator
            if end_instruction["dest_label"] == "app_label":
                if configuration.path_include_app == False:
                    handler.v2.return_handle(configuration, None)
                    # Reach end block
                    leave_block(current_block)
                    return
                else:

                    # Check if the validator can be bypassed through calling the clear state program.
                    # This is because the failure of the clear state transaction will only cause this transaction to be reverted, 
                    # and other transactions in the atomic transaction group can still be successfully executed.
                    if clear_state_constraint(configuration) and show_clear_state_message == False:
                        show_clear_state_message = True
                        print("\033[1;32;47mValidator may be bypassed through clear state transaction\033[0m")
                        #handler.v2.return_handle(configuration, None)
                        #leave_block(current_block)
                        #return
                    
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
            
            # Store the stack frame
            configuration.frame_stack_push(len(configuration.stack))

            target = int(end_instruction["params"][0])

            # Maintain stack frame balance
            if runtime.instructions[target]["type"] != "proto":
                configuration.proto_arg.append(-1)
                configuration.proto_return.append(-1)

            jump_to_block(configuration, target)
        
        elif end_instruction["type"] == "retsub":
            args = configuration.proto_arg.pop()
            returns = configuration.proto_return.pop()
            frame = configuration.frame_stack_pop()

            # Remove the args and redundant return values
            try:
                if returns != -1:
                    current_deep = len(configuration.stack)
                    if current_deep >= frame + returns:
                        configuration.stack = configuration.stack[:frame + returns]
                if args != -1:
                    configuration.stack = configuration.stack[:frame-args] + configuration.stack[frame : frame + returns]
            except:
                log.info("ConfigurationError: invalid stack operation (retsub)")
                leave_block(current_block)
                return

            trace(configuration, end_instruction)
            target = configuration.call_stack_pop()
            
            jump_to_block(configuration, target)

        elif end_instruction["type"] == "switch":
            trace(configuration, end_instruction)

            # Try to jump to every possible branch
            branch = configuration.stack_pop("uint")
            for index in range(len(end_instruction["params"])):
                target = int(end_instruction["params"][index])
                cond = (branch == index)
                cond_jump_to_block(configuration, target, cond)

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
                handler.v2.return_handle(configuration, None)
            
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
