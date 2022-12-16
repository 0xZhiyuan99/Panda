import util
import memory
import runtime
import logging
import signal
import setting
import z3

log = logging.getLogger(__name__)


class ConfigurationError(Exception):
    def __init__(self):
        if setting.DEBUG_MODE == True:
            print("Instruction: ", runtime.instructions[runtime.pc])
            #exit(runtime.CONFIGURATION_ERROR)

class Timeout:
    """Timeout class using ALARM signal."""

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)

    def _handle_timeout(self, signum, frame):
        runtime.end_process()


class BasicBlock:
    def __init__(self, instructions):
        if len(instructions) == 0:
            log.critical("Find empty basic block!")
            exit(runtime.CONSTRUCT_BASIC_BLOCK_FAILED)
        self.insturctions = util.deepcopy(instructions)
        instructions_list = list(self.insturctions.items())
        self.size = len(self.insturctions)
        self.start_address = instructions_list[0][0]
        self.end_address = instructions_list[self.size-1][0]
        self.access_count = 0
        if len(runtime.instructions) <= self.end_address + 1:
            self.adjacent_block_address = -1
        else:
            self.adjacent_block_address = self.end_address + 1
            

        # Used for debugging
        self.start_line_number = instructions_list[0][1]["line_number"]
        self.end_line_number = instructions_list[self.size-1][1]["line_number"]

    def display(self):
        print("===========================")
        print("Address range: {} - {}".format(self.start_address, self.end_address))
        print("Line number range: {} - {}".format(self.start_line_number, self.end_line_number))
        print("===========================")


class Configuration:
    def __init__(self, **kwargs):
        if len(kwargs) == 0:
            self.app_area = False
            self.path_include_app = False
            self.current_block_address = 0
            self.current_block_depth = 0
            self.total_cost = 0
            self.uint_block = []
            self.bytes_block = []
            self.stack = []
            self.call_stack = []
            self.frame_stack = []
            self.proto_arg = []
            self.proto_return = []
            self.symbolic_inner_txn_fee = False
            self.app_call_symbolic_index = -1
            self.app_call_symbolic_index_assigned = False
            self.symbolic_hash_variable_used = False
            self.opcode_record = {
                "itxn_submit": False,
                "app_global_put": False,
                "app_local_put": False,
                "app_local_get": False,
                "timestamp": False,
                "local_users": [],
                "gtxn_pay_index": [],
                "gtxn_axfer_index": [],
                "gtxn_index": [],
            }
            self.global_state_return_uint = z3.Array('global_state_return_uint', z3.StringSort(), z3.BitVecSort(64))
            self.global_state_return_bytes = z3.Array('global_state_return_bytes', z3.StringSort(), z3.StringSort())
            self.local_state_uint_return_uint = z3.Array('local_state_uint_return_uint', z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.BitVecSort(64)))
            self.local_state_uint_return_bytes = z3.Array('local_state_uint_return_bytes', z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.StringSort()))
            self.local_state_bytes_return_uint = z3.Array('local_state_bytes_return_uint', z3.StringSort(), z3.ArraySort(z3.StringSort(), z3.BitVecSort(64)))
            self.local_state_bytes_return_bytes = z3.Array('local_state_bytes_return_bytes', z3.StringSort(), z3.ArraySort(z3.StringSort(), z3.StringSort()))
            self.scratch_space_return_uint = z3.Array('scratch_space_return_uint', z3.BitVecSort(64), z3.BitVecSort(64) )
            self.scratch_space_return_bytes = z3.Array('scratch_space_return_bytes', z3.BitVecSort(64), z3.StringSort() )
        else:
            for key in kwargs:
                setattr(self, key, kwargs[key])

    def copy(self):
        _kwargs = util.deepcopy(self.__dict__)
        return Configuration(**_kwargs)

    def get_uint(self, key):
        try:
            return self.uint_block[key]
        except:
            log.error("Undefined unit block")
            exit(runtime.UNDEFINED_UINT_BLOCK)

    def get_bytes(self, key):
        try:
            return self.bytes_block[key]
        except:
            log.error("Undefined bytes block")
            exit(runtime.UNDEFINED_BYTES_BLOCK)
    
    def call_stack_push(self, val):
        self.call_stack.append(val)

    def call_stack_pop(self):
        if len(self.call_stack) == 0:
            log.info("ConfigurationError: invalid call stack operation")
            raise ConfigurationError
        return self.call_stack.pop()

    def frame_stack_push(self, val):
        self.frame_stack.append(val)

    def frame_stack_pop(self):
        if len(self.frame_stack) == 0:
            log.info("ConfigurationError: invalid frame stack operation")
            raise ConfigurationError
        return self.frame_stack.pop()

    # Simplify the symbolic value when it is pushed onto the stack
    def stack_push(self, val):
        self.stack.append(val)
        if val["type"] != "undefined":
            val["value"] = z3.simplify(val["value"])
        if len(self.stack) > setting.MAX_STACK_DEPTH:
            log.info("ConfigurationError: stack exceeded maximum size limit")
            raise ConfigurationError

    def stack_pop(self, val_type):
        if len(self.stack) == 0:
            log.info("ConfigurationError: invalid stack operation (pop)")
            raise ConfigurationError
        val_dict = self.stack.pop()

        # Generate a z3 variable according to the type
        if val_type == "original":
            return val_dict
        elif val_dict["type"] == "undefined":
            memory.Define(val_dict, val_type, self)
        elif val_dict["type"] != val_type:
            log.info("ConfigurationError: Type mismatch")
            raise ConfigurationError

        if val_type == "uint" and ( not z3.is_bv(val_dict["value"]) ):
            log.critical("Internal type mismatch")
            exit(runtime.INTERNAL_TYPE_MISMATCH)
        elif val_type == "bytes" and ( not z3.is_string(val_dict["value"]) ):
            log.critical("Internal type mismatch")
            exit(runtime.INTERNAL_TYPE_MISMATCH)
        
        return val_dict["value"]

    # Pop two same type value
    def stack_pop2(self, val_type="bytes"):
        if len(self.stack) < 2:
            log.info("ConfigurationError: invalid stack operation (pop2)")
            raise ConfigurationError
        val_dict1 = self.stack.pop()
        val_dict2 = self.stack.pop()

        if val_dict1["type"] == "undefined" and val_dict2["type"] == "undefined":
            log.info("ConfigurationError: Pop two undefined variables")
            memory.Define(val_dict1, val_type, self)

            # Check if the two val_dict point to the same variable
            if val_dict2["type"] == "undefined":
                memory.Define(val_dict2, val_type, self)
        else:

            # The two variable must have the same type
            if val_dict1["type"] == "undefined":
                memory.Define(val_dict1, val_dict2["type"], self)
            if val_dict2["type"] == "undefined":
                memory.Define(val_dict2, val_dict1["type"], self)

        if val_dict1["type"] != val_dict2["type"]:
            log.info("ConfigurationError: Type mismatch")
            raise ConfigurationError
        
        return val_dict1["value"], val_dict2["value"]
    
    def stack_get(self, cursor):
        if len(self.stack) >= abs(cursor) and cursor < 0:
            return self.stack[cursor]
        elif len(self.stack) > cursor and cursor >= 0:
            return self.stack[cursor]
        else:
            log.info("ConfigurationError: invalid stack operation (get)")
            raise ConfigurationError
