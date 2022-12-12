import z3
import z3.z3util
import os
import time
import analyzer
import logging

log = logging.getLogger(__name__)


# define error code
PARSE_INSTRUCTIONS_FAILED = 101
PARSE_LABELS_FAILED = 102
CONSTRUCT_BASIC_BLOCK_FAILED = 103
INVALID_GLOBAL_PARAMETERS = 104
EXECUTE_FAILED = 105
INCORRECT_BLOCK_CONSTRUCTION = 106
CONNECT_TO_ALGOD_SERVER_FAILED = 107
UNDEFINED_UINT_BLOCK = 108
UNDEFINED_BYTES_BLOCK = 109
INVALID_BYTEC_BLOCK = 110
INTERNAL_JUMP_INSTRUCTION = 111
INVALID_SCRATCH_INDEX = 112
#INVALID_COVER_PARAM = 113
INVALID_INTCBLOCK = 114
UNRECOGNISED_OPCODE = 115
INTERNAL_TYPE_MISMATCH = 116
#UNRECOGNISED_DATA_FORMAT = 117
INVALID_OPCODE = 118
CONFIGURATION_ERROR = 119
UNRECOGNISED_DEFINITION_TYPE = 120
INVALID_ASSET_ID = 121
UNKNOWN_DETECTION_RULE = 122



# A simulator of Z3 solver with additional records
class Solver:
    def __init__(self):
        self.solver = z3.Solver()
        self.path_constraint_list = [[]]

    def add(self, constraint):
        if type(constraint) == z3.z3.BoolRef:
            constraint = z3.simplify(constraint)

        index = len(self.path_constraint_list) - 1
        self.path_constraint_list[index].append(constraint)
        return self.solver.add(constraint)

    def push(self):
        self.path_constraint_list.append([])
        return self.solver.push()

    def pop(self):
        self.path_constraint_list.pop()
        return self.solver.pop()

    def check(self):
        try:
            flag = self.solver.check()
            return flag
        except:
            return z3.unsat

    def model(self):
        return self.solver.model()

    def set(self, key, value):
        return self.solver.set(key, value)

    def satisfy(self, constraints, output=False):
        self.push()
        self.add(constraints)
        flag = self.check()
        if flag == z3.sat and output == True:
            print(self.model())
        if flag == z3.unknown:
            log.info("Z3 timeout")
        self.pop()
        return flag

    def get_constraints(self):
        constraints = []
        for depth in range(len(self.path_constraint_list)):
            for expr in self.path_constraint_list[depth]:
                constraints.append(expr)
        return constraints
    
    def display(self):
        for depth in range(len(self.path_constraint_list)):
            #print(self.path_constraint_list[depth])
            for expr in self.path_constraint_list[depth]:
                print(expr)
                if not z3.is_expr(expr):
                    continue
                list_vars = z3.z3util.get_vars(expr)
                if len(list_vars) > 0:
                    for var in list_vars:
                        pass
                        #print(var)


start_time = time.time()
block_search_record = []
leaves_number = 0
total_path = 0
feasible_path = 0
pc = 1

solver = Solver()
instructions = {}
labels = {}
vertices = {}
version = 0

app_call_group_index = -1

itxn_field = {}
itxn_index = 0
for i in range(16):
    itxn_field[i] = {
        "ApplicationArgs": [],
        "Accounts": [],
        "Assets": [],
        "Applications": [],
        "Logs": [],
        "ApprovalProgramPages": [],
        "ClearStateProgramPages": [],
    }

lsig_address = None

def end_process():
    end_time = time.time()
    # Output the statistic info
    print("\033[0;30;47m", flush=True)
    print("======================================", flush=True)
    opcode_kinds = len(set([ x["type"] for x in list(instructions.values())[:-1] ]))
    print('\033[0;34;47mDone Symbolic Execution (Time: {}, Opcodes: {}({}), Leaves Number: {}, Total Path: {}, Feasible Path: {})'.format(
                format(end_time - start_time, '.2f'), len(instructions)-1, opcode_kinds, leaves_number, 
                total_path, feasible_path), flush=True )
    bug_list = []
    for i in range(len(analyzer.message_record)):
        output = analyzer.message_record[i] + "\nBacktrace: " + analyzer.backtrace_record[i]
        bug_list.append(output)
    bug_list.sort(reverse=True)
    for bug in bug_list:
        print(bug, flush=True)
    for i in range(len(analyzer.vulnerable_asset_record)):
        print(analyzer.vulnerable_asset_record[i], flush=True)
    print("\033[0;30;47m======================================\033[0m\n", flush=True)
    os._exit(0)


def get_group_index(configuration):
    if app_call_group_index != -1:
        if app_call_group_index == -2:
            index = z3.BitVec("GroupIndex", 64)
        if app_call_group_index == -3:      
            if configuration.app_call_symbolic_index_assigned == False:
                index = z3.BitVec("GroupIndex", 64)
            else:     
                index = configuration.app_call_symbolic_index
        elif configuration.app_area == False:
            index = z3.BitVec("GroupIndex", 64)
        else:
            index = z3.BitVecVal(app_call_group_index, 64)
    else:
        index = z3.BitVec("GroupIndex", 64)
    return index

def get_group_index_string(configuration):
    if app_call_group_index != -1:
        if app_call_group_index == -2:
            index = "GroupIndex"
        if app_call_group_index == -3:      
            if configuration.app_call_symbolic_index_assigned == False:
                index = "GroupIndex"
            else:
                index = str(configuration.app_call_symbolic_index)
        elif configuration.app_area == False:
            index = "GroupIndex"
        else:
            index = str(app_call_group_index)
    else:
        index = "GroupIndex"
    return index

