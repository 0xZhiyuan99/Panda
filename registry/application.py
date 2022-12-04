
import z3
import setting
import runtime
import memory
import logging
from .parser import *

log = logging.getLogger(__name__)


def arbitrary_update_vulnerability(configuration):
    if configuration.opcode_record["app_local_get"] == True:
        return False
    
    new_constraints = []
    new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 4 ) # UpdateApplication
    new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

    if runtime.solver.satisfy(new_constraints) == z3.sat:
        return not is_constrained_string(setting.sender_address)
    else:
        return False

def arbitrary_delete_vulnerability(configuration):
    if configuration.opcode_record["app_local_get"] == True:
        return False
    
    new_constraints = []
    new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 5 ) # DeleteApplication
    new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

    if runtime.solver.satisfy(new_constraints) == z3.sat:
        return not is_constrained_string(setting.sender_address)
    else:
        return False

def unchecked_group_size_vulnerability(configuration):
    new_constraints = []

    # The transactions and state changes can be reverted
    if configuration.opcode_record["itxn_submit"] == True \
         or configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        new_constraints.append( z3.BitVec("global_GroupSize", 64) == 17 ) # MaxTxGroupSize + 1 == 17
        new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )
        new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 0 ) # NoOp

        if runtime.solver.satisfy(new_constraints) == z3.sat:
            return True
        else:
            return False

    return False

def force_clear_state_vulnerability(configuration):
    new_constraints = []
    if configuration.opcode_record["itxn_submit"] == True \
        or configuration.opcode_record["app_global_put"] == True \
        or configuration.opcode_record["app_local_put"] == True:
        local_user_list = list(set(configuration.opcode_record["local_users"]))
        for local_user in local_user_list:
            if local_user != str(z3.StringVal(setting.sender_address)) and \
                local_user != str(z3.BitVecVal(0, 64)):
                new_constraints.append(z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0)
                new_constraints.append(z3.Or(z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 0,  # NoOp
                                        z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 2) )  # CloseOut
                
                if runtime.solver.satisfy(new_constraints) == z3.sat:
                    print("\033[1;32;47mOther local user: {}\033[0m".format(local_user))
                    return True

    return False


def unchecked_payment_receiver_vulnerability(configuration):
    if configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        gtxn_list = list(set(configuration.opcode_record["gtxn_index"]))
        for index in gtxn_list:
            if is_payment_transaction(index) == False:
                continue
            #if is_constrained_var("gtxn_XferAsset[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_AssetAmount[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_AssetSender[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_AssetReceiver[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
            #    continue

            gtxn_type = z3.Select(memory.gtxn_Type, index)
            gtxn_enum = z3.Select(memory.gtxn_TypeEnum, index)
            gtxn_receiver = z3.Select(memory.gtxn_Receiver, index)

            current_constraint = z3.And(gtxn_type == z3.StringVal("pay"), gtxn_enum == z3.BitVecVal(1, 64),
                                            gtxn_receiver == z3.StringVal("\xcc" * 32),
                                            z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

            if runtime.solver.satisfy(current_constraint) == z3.sat:
                if not is_constrained_var("gtxn_Receiver[{}]".format(index)):
                    print("\033[1;32;47mUnchecked payment receiver {}: {}\033[0m".format(gtxn_list, index))
                    return True
    return False


def unchecked_asset_receiver_vulnerability(configuration):
    if configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        gtxn_list = list(set(configuration.opcode_record["gtxn_index"]))
        for index in gtxn_list:
            if is_asset_transfer_transaction(index) == False:
                continue
            #if is_constrained_var("gtxn_Amount[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_Receiver[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
            #    or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
            #    continue

            gtxn_type = z3.Select(memory.gtxn_Type, index)
            gtxn_enum = z3.Select(memory.gtxn_TypeEnum, index)
            gtxn_AssetReceiver = z3.Select(memory.gtxn_AssetReceiver, index)

            current_constraint = z3.And(gtxn_type == z3.StringVal("axfer"), gtxn_enum == z3.BitVecVal(4, 64),
                                            gtxn_AssetReceiver == z3.StringVal("\xdd" * 32),
                                            z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

            if runtime.solver.satisfy(current_constraint) == z3.sat:
                if not is_constrained_var("gtxn_AssetReceiver[{}]".format(index)):
                    print("\033[1;32;47mUnchecked asset receiver {}: {}\033[0m".format(gtxn_list, index))
                    return True
    return False

def time_stamp_dependeceny_vulnerability(configuration):
    new_constraints = []
    if configuration.opcode_record["timestamp"] == True:
        new_constraints.append(z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0)
        new_constraints.append(z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 0) # NoOp

        if runtime.solver.satisfy(new_constraints) == z3.sat:
            return True
        else:
            return False
    else:
        return False

