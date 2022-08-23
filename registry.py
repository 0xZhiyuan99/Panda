
import z3
import setting
import runtime
import memory
import logging

log = logging.getLogger(__name__)



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

def unchecked_transaction_fee_in_lsig(configuration):
    # Sometimes the transaction fee is not limit to a concrete value but other symbolic values
    # As a result, the only way to check is check if "gtxn_Fee[GroupIndex]" is part of the path constraints

    #for expr in runtime.solver.get_constraints():
    #    if "gtxn_Fee[GroupIndex]" in str(expr):
    #        return [False]
    #    print(str(z3.z3util.get_vars(expr)))

    # new_constraints.append( z3.Select(memory.gtxn_Fee, z3.BitVec("GroupIndex", 64)) > 100000 )
    
    if is_constrained_var("gtxn_Fee[GroupIndex]") == True:
        return False
    else:
        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)
        
        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False

        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True

        for index in gtxn_index_list:
            if is_constrained_var("gtxn_Fee[{}]".format(index)) == False:
                current_constraint = z3.And(z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\xbb" * 32 ),
                                    z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_transaction_fee index:", index)
                    return True
        return False


def unchecked_transaction_fee_in_lsig2(configuration):
    if is_constrained_var("gtxn_Fee[GroupIndex]") == True:
        return False
    else:
        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)
        
        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False

        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True

        for index in gtxn_index_list:
            if is_constrained_var("gtxn_Fee[{}]".format(index)) == False:
                current_constraint = z3.BitVec("GroupIndex", 64) == index

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_transaction_fee index:", index)
                    return True
        return False

def unchecked_RekeyTo_in_lsig(configuration):

    # It seems that TEAL version 1 does not support rekey-to
    if runtime.version > 1:
        if is_constrained_var("gtxn_RekeyTo[GroupIndex]") == True:
            return False
        else:
            current_constraint = z3.And(z3.Select(memory.gtxn_CloseRemainderTo, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "\x00" * 32 ),
                                    z3.Select(memory.gtxn_AssetCloseTo, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "\x00" * 32 ) )
            flag = runtime.solver.satisfy(current_constraint)
            if flag == z3.unsat:
                return False
            elif flag == z3.unknown:
                log.info("Z3 timeout")
                return False


            gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
            constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

            if configuration.app_area == True:
                if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                    return False

            flag = runtime.solver.satisfy(constraint)
            if flag == z3.sat:
                return True

            for index in gtxn_index_list:
                if is_constrained_var("gtxn_RekeyTo[{}]".format(index)) == False:
                    current_constraint = z3.And(z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\xbb" * 32 ),
                                    z3.BitVec("GroupIndex", 64) == index,
                                    z3.Select(memory.gtxn_CloseRemainderTo, index) == z3.StringVal( "\x00" * 32 ),
                                    z3.Select(memory.gtxn_AssetCloseTo, index) == z3.StringVal( "\x00" * 32 ) )
                
                    flag = runtime.solver.satisfy(current_constraint)
                    if flag == z3.sat:
                        print("unchecked_RekeyTo index:", index)
                        return True
            return False
    else:
        return False


def unchecked_RekeyTo_in_lsig2(configuration):

    # It seems that TEAL version 1 does not support rekey-to
    if runtime.version > 1:
        if is_constrained_var("gtxn_RekeyTo[GroupIndex]") == True:
            return False
        else:
            current_constraint = z3.And(z3.Select(memory.gtxn_CloseRemainderTo, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "\x00" * 32 ),
                                    z3.Select(memory.gtxn_AssetCloseTo, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "\x00" * 32 ) )
            flag = runtime.solver.satisfy(current_constraint)
            if flag == z3.unsat:
                return False
            elif flag == z3.unknown:
                log.info("Z3 timeout")
                return False


            gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
            constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

            if configuration.app_area == True:
                if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                    return False

            flag = runtime.solver.satisfy(constraint)
            if flag == z3.sat:
                return True

            for index in gtxn_index_list:
                if is_constrained_var("gtxn_RekeyTo[{}]".format(index)) == False:
                    current_constraint = z3.And(z3.BitVec("GroupIndex", 64) == index,
                                    z3.Select(memory.gtxn_CloseRemainderTo, index) == z3.StringVal( "\x00" * 32 ),
                                    z3.Select(memory.gtxn_AssetCloseTo, index) == z3.StringVal( "\x00" * 32 ) )
                
                    flag = runtime.solver.satisfy(current_constraint)
                    if flag == z3.sat:
                        print("unchecked_RekeyTo index:", index)
                        return True
            return False
    else:
        return False

def unchecked_CloseRemainderTo_in_lsig(configuration):
    if is_constrained_var("gtxn_CloseRemainderTo[GroupIndex]") == True:
        return False
    else:
        current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, z3.BitVec("GroupIndex", 64)) == 1,
                                z3.Select(memory.gtxn_Type, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "pay" ) )
        flag = runtime.solver.satisfy(current_constraint)
        if flag == z3.unsat:
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout")
            return False

        # Check the implicit transaction type
        if is_constrained_var("gtxn_XferAsset[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetAmount[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetSender[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetReceiver[GroupIndex]") == True:
            return False
        
        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False

        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True

        for index in gtxn_index_list:

            # Check the implicit transaction type
            if is_constrained_var("gtxn_XferAsset[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetAmount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetSender[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetReceiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue


            if is_constrained_var("gtxn_CloseRemainderTo[{}]".format(index)) == False:
                current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, index) == 1,
                                z3.Select(memory.gtxn_Type, index) == z3.StringVal( "pay" ),
                                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\xbb" * 32 ),
                                z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_CloseRemainderTo index:", index)
                    return True
        return False

def unchecked_CloseRemainderTo_in_lsig2(configuration):
    if is_constrained_var("gtxn_CloseRemainderTo[GroupIndex]") == True:
        return False
    else:
        current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, z3.BitVec("GroupIndex", 64)) == 1,
                                z3.Select(memory.gtxn_Type, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "pay" ) )
        flag = runtime.solver.satisfy(current_constraint)
        if flag == z3.unsat:
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout")
            return False

        # Check the implicit transaction type
        if is_constrained_var("gtxn_XferAsset[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetAmount[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetSender[GroupIndex]") == True \
            or is_constrained_var("gtxn_AssetReceiver[GroupIndex]") == True:
            return False
        
        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False

        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True

        for index in gtxn_index_list:

            # Check the implicit transaction type
            if is_constrained_var("gtxn_XferAsset[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetAmount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetSender[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetReceiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue


            if is_constrained_var("gtxn_CloseRemainderTo[{}]".format(index)) == False:
                current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, index) == 1,
                                z3.Select(memory.gtxn_Type, index) == z3.StringVal( "pay" ),
                                z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_CloseRemainderTo index:", index)
                    return True
        return False


def unchecked_AssetCloseTo_in_lsig(configuration):
    if is_constrained_var("gtxn_AssetCloseTo[GroupIndex]") == True:
        return False
    else:
        current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, z3.BitVec("GroupIndex", 64)) == 4,
                                z3.Select(memory.gtxn_Type, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "axfer" ) )
        flag = runtime.solver.satisfy(current_constraint)
        if flag == z3.unsat:
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout")
            return False

        
        # Check the implicit transaction type
        if is_constrained_var("gtxn_Amount[GroupIndex]") == True \
            or is_constrained_var("gtxn_Receiver[GroupIndex]") == True:
            return False

        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False
        
        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True
        
        for index in gtxn_index_list:

            # Check the implicit transaction type
            if is_constrained_var("gtxn_Amount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_Receiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue

            if is_constrained_var("gtxn_AssetCloseTo[{}]".format(index)) == False:
                current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, index) == 4,
                                z3.Select(memory.gtxn_Type, index) == z3.StringVal( "axfer" ),
                                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\xbb" * 32 ),
                                z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_AssetCloseTo index:", index)
                    return True
        return False

def unchecked_AssetCloseTo_in_lsig2(configuration):
    if is_constrained_var("gtxn_AssetCloseTo[GroupIndex]") == True:
        return False
    else:
        current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, z3.BitVec("GroupIndex", 64)) == 4,
                                z3.Select(memory.gtxn_Type, z3.BitVec("GroupIndex", 64)) == z3.StringVal( "axfer" ) )
        flag = runtime.solver.satisfy(current_constraint)
        if flag == z3.unsat:
            return False
        elif flag == z3.unknown:
            log.info("Z3 timeout")
            return False

        
        # Check the implicit transaction type
        if is_constrained_var("gtxn_Amount[GroupIndex]") == True \
            or is_constrained_var("gtxn_Receiver[GroupIndex]") == True:
            return False

        gtxn_index_list = list(set(configuration.opcode_record["gtxn_index"]))
        constraint = len(gtxn_index_list) < z3.BitVec("global_GroupSize", 64)

        if configuration.app_area == True:
            if is_constrained_var("gtxn_Sender[{}]".format(runtime.app_call_group_index)) == True:
                return False
        
        flag = runtime.solver.satisfy(constraint)
        if flag == z3.sat:
            return True
        
        for index in gtxn_index_list:

            # Check the implicit transaction type
            if is_constrained_var("gtxn_Amount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_Receiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue

            if is_constrained_var("gtxn_AssetCloseTo[{}]".format(index)) == False:
                current_constraint = z3.And(z3.Select(memory.gtxn_TypeEnum, index) == 4,
                                z3.Select(memory.gtxn_Type, index) == z3.StringVal( "axfer" ),
                                z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_AssetCloseTo index:", index)
                    return True
        return False



def arbitrary_update_vulnerability(configuration):
    new_constraints = []
    new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 4 ) # UpdateApplication
    new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

    flag = runtime.solver.satisfy(new_constraints)
    if flag == z3.sat:
        return not is_constrained_string(setting.sender_address)
    else:
        if flag == z3.unknown:
            log.info("Z3 timeout")
        return False

def arbitrary_delete_vulnerability(configuration):
    new_constraints = []
    new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 5 ) # DeleteApplication
    new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

    flag = runtime.solver.satisfy(new_constraints)
    if flag == z3.sat:
        return not is_constrained_string(setting.sender_address)
    else:
        if flag == z3.unknown:
            log.info("Z3 timeout")
        return False

def unchecked_group_size_vulnerability(configuration):
    new_constraints = []

    # The transactions and state changes can be reverted
    if configuration.opcode_record["itxn_submit"] == True \
         or configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        new_constraints.append( z3.BitVec("global_GroupSize", 64) == 16 ) # MaxTxGroupSize
        new_constraints.append( z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )
        new_constraints.append( z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 0 ) # NoOp

        flag = runtime.solver.satisfy(new_constraints)
        if flag == z3.sat:
            return True
        else:
            if flag == z3.unknown:
                log.info("Z3 timeout")
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
                
                flag = runtime.solver.satisfy(new_constraints)
                if flag == z3.sat:
                    print("local_user:", local_user)
                    return True
                else:
                    if flag == z3.unknown:
                        log.info("Z3 timeout")
    return False


def unchecked_payment_receiver_vulnerability(configuration):
    if configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        gtxn_list = list(set(configuration.opcode_record["gtxn_index"]))
        for index in gtxn_list:
            if is_constrained_var("gtxn_XferAsset[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetAmount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetSender[{}]".format(index)) == True \
                or is_constrained_var("gtxn_AssetReceiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue

            gtxn_type = z3.Select(memory.gtxn_Type, index)
            gtxn_enum = z3.Select(memory.gtxn_TypeEnum, index)
            gtxn_receiver = z3.Select(memory.gtxn_Receiver, index)

            current_constraint = z3.And(gtxn_type == z3.StringVal("pay"), gtxn_enum == z3.BitVecVal(1, 64),
                                            gtxn_receiver == z3.StringVal("\xcc" * 32),
                                            z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

            flag = runtime.solver.satisfy(current_constraint)
            if flag == z3.unsat:
                continue
            else:
                if flag == z3.unknown:
                    log.info("Z3 timeout")
                    continue
                if not is_constrained_var("gtxn_Receiver[{}]".format(index)):
                    print("payment{}: {}".format(gtxn_list, index))
                    return True
    return False


def unchecked_asset_receiver_vulnerability(configuration):
    if configuration.opcode_record["app_global_put"] == True \
         or configuration.opcode_record["app_local_put"] == True:
        gtxn_list = list(set(configuration.opcode_record["gtxn_index"]))
        for index in gtxn_list:

            if is_constrained_var("gtxn_Amount[{}]".format(index)) == True \
                or is_constrained_var("gtxn_Receiver[{}]".format(index)) == True \
                or is_constrained_var("gtxn_ApplicationID[{}]".format(index)) == True \
                or is_constrained_var("gtxn_OnCompletion[{}]".format(index)) == True:
                continue

            gtxn_type = z3.Select(memory.gtxn_Type, index)
            gtxn_enum = z3.Select(memory.gtxn_TypeEnum, index)
            gtxn_AssetReceiver = z3.Select(memory.gtxn_AssetReceiver, index)

            current_constraint = z3.And(gtxn_type == z3.StringVal("axfer"), gtxn_enum == z3.BitVecVal(4, 64),
                                            gtxn_AssetReceiver == z3.StringVal("\xdd" * 32),
                                            z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0 )

            flag = runtime.solver.satisfy(current_constraint)
            if flag == z3.unsat:
                continue
            else:
                if flag == z3.unknown:
                    log.info("Z3 timeout")
                    continue
                if not is_constrained_var("gtxn_AssetReceiver[{}]".format(index)):
                    print("asset{}: {}".format(gtxn_list, index))
                    return True
    return False

def time_stamp_dependeceny_vulnerability(configuration):
    new_constraints = []
    if configuration.opcode_record["timestamp"] == True:
        new_constraints.append(z3.Select(memory.gtxn_ApplicationID, z3.BitVec("GroupIndex", 64)) != 0)
        new_constraints.append(z3.Select(memory.gtxn_OnCompletion, z3.BitVec("GroupIndex", 64)) == 0) # NoOp

        flag = runtime.solver.satisfy(new_constraints)
        if flag == z3.sat:
            return True
        else:
            if flag == z3.unknown:
                log.info("Z3 timeout")
            return False
    else:
        return False


