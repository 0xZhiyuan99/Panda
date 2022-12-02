import logging
import runtime

log = logging.getLogger(__name__)


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

def show_backtrace():
    backtrace = []
    for pair in runtime.block_search_record:
        start = runtime.instructions[pair[0]]["line_number"]
        end = runtime.instructions[pair[1]]["line_number"]
        backtrace.append("({}-{})".format(start,end))
    print('->'.join(backtrace))