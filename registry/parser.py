import z3
import runtime
import logging

def get_string_var_list(expr, result):
    if z3.is_string_value(expr):
        result.append(expr)
        return
    if expr.num_args() > 0:
        for i in range(expr.num_args()):
            get_string_var_list(expr.arg(i), result)

def is_constrained_string(var):
    constrained_string_list = []
    for expr in runtime.solver.get_constraints():
        get_string_var_list(expr, constrained_string_list)
    
    for constrained_string in constrained_string_list:
        if constrained_string.as_string() == var:
            return True
    return False

def get_array_var_list(expr, result):
    if z3.is_select(expr):
        result.append(expr)
        return
    if expr.num_args() > 0:
        for i in range(expr.num_args()):
            get_array_var_list(expr.arg(i), result)

def is_constrained_var(var):
    constrained_var_list = []
    for expr in runtime.solver.get_constraints():
        get_array_var_list(expr, constrained_var_list)
    
    for constrained_var in constrained_var_list:
        if str(constrained_var) == var:
            return True
    return False

