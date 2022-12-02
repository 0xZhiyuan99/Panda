
import z3
import runtime
import memory
import logging
from .parser import *

log = logging.getLogger(__name__)


def unchecked_transaction_fee_in_lsig(configuration):
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
                current_constraint = z3.And(z3.Select(memory.gtxn_Sender, index) == z3.StringVal( runtime.lsig_address ),
                                    z3.BitVec("GroupIndex", 64) == index )

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
                    current_constraint = z3.And(z3.Select(memory.gtxn_Sender, index) == z3.StringVal( runtime.lsig_address ),
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
                                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( runtime.lsig_address ),
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
                                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( runtime.lsig_address ),
                                z3.BitVec("GroupIndex", 64) == index )

                flag = runtime.solver.satisfy(current_constraint)
                if flag == z3.sat:
                    print("unchecked_AssetCloseTo index:", index)
                    return True
        return False

