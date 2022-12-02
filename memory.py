import runtime
import z3
import logging

log = logging.getLogger(__name__)

# balance_handle
balance_array_uint = z3.Array('balance_array_uint', z3.BitVecSort(64), z3.BitVecSort(64))
balance_array_bytes = z3.Array('balance_array_bytes', z3.StringSort(), z3.BitVecSort(64))

# min_balance_handle
min_balance_array_uint = z3.Array('min_balance_array_uint', z3.BitVecSort(64), z3.BitVecSort(64))
min_balance_array_bytes = z3.Array('min_balance_array_bytes', z3.StringSort(), z3.BitVecSort(64))

# asset_params_get_handle
AssetTotal = z3.Array('AssetTotal', z3.BitVecSort(64), z3.BitVecSort(64))
AssetDecimals = z3.Array('AssetDecimals', z3.BitVecSort(64), z3.BitVecSort(64))
AssetDefaultFrozen = z3.Array('AssetDefaultFrozen', z3.BitVecSort(64), z3.BitVecSort(64))
AssetUnitName = z3.Array('AssetUnitName', z3.BitVecSort(64), z3.StringSort())
AssetName = z3.Array('AssetName', z3.BitVecSort(64), z3.StringSort())
AssetURL = z3.Array('AssetURL', z3.BitVecSort(64), z3.StringSort())
AssetMetadataHash = z3.Array('AssetMetadataHash', z3.BitVecSort(64), z3.StringSort())
AssetManager = z3.Array('AssetManager', z3.BitVecSort(64), z3.StringSort())
AssetReserve = z3.Array('AssetReserve', z3.BitVecSort(64), z3.StringSort())
AssetFreeze = z3.Array('AssetFreeze', z3.BitVecSort(64), z3.StringSort())
AssetClawback = z3.Array('AssetClawback', z3.BitVecSort(64), z3.StringSort())
AssetCreator = z3.Array('AssetCreator', z3.BitVecSort(64), z3.StringSort())

# app_params_get_handle
AppGlobalNumUint_uint = z3.Array('AppGlobalNumUint_uint', z3.BitVecSort(64), z3.BitVecSort(64))
AppGlobalNumByteSlice_uint = z3.Array('AppGlobalNumByteSlice_uint', z3.BitVecSort(64), z3.BitVecSort(64))
AppLocalNumUint_uint = z3.Array('AppLocalNumUint_uint', z3.BitVecSort(64), z3.BitVecSort(64))
AppLocalNumByteSlice_uint = z3.Array('AppLocalNumByteSlice_uint', z3.BitVecSort(64), z3.BitVecSort(64))
AppExtraProgramPages_uint = z3.Array('AppExtraProgramPages_uint', z3.BitVecSort(64), z3.BitVecSort(64))
AppApprovalProgram_uint = z3.Array('AppApprovalProgram_uint', z3.BitVecSort(64), z3.StringSort())
AppClearStateProgram_uint = z3.Array('AppClearStateProgram_uint', z3.BitVecSort(64), z3.StringSort())
AppAddress_uint = z3.Array('AppAddress_uint', z3.BitVecSort(64), z3.StringSort())
AppGlobalNumUint_bytes = z3.Array('AppGlobalNumUint_bytes', z3.StringSort(), z3.BitVecSort(64))
AppGlobalNumByteSlice_bytes = z3.Array('AppGlobalNumByteSlice_bytes', z3.StringSort(), z3.BitVecSort(64))
AppLocalNumUint_bytes = z3.Array('AppLocalNumUint_bytes', z3.StringSort(), z3.BitVecSort(64))
AppLocalNumByteSlice_bytes = z3.Array('AppLocalNumByteSlice_bytes', z3.StringSort(), z3.BitVecSort(64))
AppExtraProgramPages_bytes = z3.Array('AppExtraProgramPages_bytes', z3.StringSort(), z3.BitVecSort(64))
AppApprovalProgram_bytes = z3.Array('AppApprovalProgram_bytes', z3.StringSort(), z3.StringSort())
AppClearStateProgram_bytes = z3.Array('AppClearStateProgram_bytes', z3.StringSort(), z3.StringSort())
AppAddress_bytes = z3.Array('AppAddress_bytes', z3.StringSort(), z3.StringSort())

# args_handle
args = z3.Array('args', z3.BitVecSort(64), z3.StringSort())

# gaid_handle gaids_handle
gaid = z3.Array('gaid', z3.BitVecSort(64), z3.BitVecSort(64))

# gload_handle gloads_handle
global_scratch_space_return_uint = z3.Array('global_scratch_space_return_uint', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)) )
global_scratch_space_return_bytes = z3.Array('global_scratch_space_return_bytes', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()) )

# app_global_get_ex_handle
global_state_ex_return_uint = z3.Array('global_state_ex_return_uint', z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.BitVecSort(64)) )
global_state_ex_return_bytes = z3.Array('global_state_ex_return_bytes', z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.StringSort()) )

# app_local_get_ex_handle
local_state_ex_uint_return_uint = z3.Array('local_state_ex_uint_return_uint',
         z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.BitVecSort(64))) )
local_state_ex_bytes_return_uint = z3.Array('local_state_ex_bytes_return_uint',
         z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.ArraySort(z3.StringSort(), z3.BitVecSort(64))) )
local_state_ex_uint_return_bytes = z3.Array('local_state_ex_uint_return_bytes',
         z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.StringSort())) )
local_state_ex_bytes_return_bytes = z3.Array('local_state_ex_bytes_return_bytes',
         z3.BitVecSort(64), z3.ArraySort(z3.StringSort(), z3.ArraySort(z3.StringSort(), z3.StringSort())) )
        

# gtxn_handle gtxns_handle
gtxn_Sender = z3.Array('gtxn_Sender', z3.BitVecSort(64), z3.StringSort())
gtxn_Fee = z3.Array('gtxn_Fee', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_FirstValid = z3.Array('gtxn_FirstValid', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_FirstValidTime = z3.Array('gtxn_FirstValidTime', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_LastValid = z3.Array('gtxn_LastValid', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_Note = z3.Array('gtxn_Note', z3.BitVecSort(64), z3.StringSort())
gtxn_Lease = z3.Array('gtxn_Lease', z3.BitVecSort(64), z3.StringSort())
gtxn_Receiver = z3.Array('gtxn_Receiver', z3.BitVecSort(64), z3.StringSort())
gtxn_Amount = z3.Array('gtxn_Amount', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_VoteFirst = z3.Array('gtxn_VoteFirst', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_VoteLast = z3.Array('gtxn_VoteLast', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_VoteKeyDilution = z3.Array('gtxn_VoteKeyDilution', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_TypeEnum = z3.Array('gtxn_TypeEnum', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_CloseRemainderTo = z3.Array('gtxn_CloseRemainderTo', z3.BitVecSort(64), z3.StringSort())
gtxn_VotePK = z3.Array('gtxn_VotePK', z3.BitVecSort(64), z3.StringSort())
gtxn_SelectionPK = z3.Array('gtxn_SelectionPK', z3.BitVecSort(64), z3.StringSort())
gtxn_Type = z3.Array('gtxn_Type', z3.BitVecSort(64), z3.StringSort())
gtxn_XferAsset = z3.Array('gtxn_XferAsset', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_AssetAmount = z3.Array('gtxn_AssetAmount', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ApplicationID = z3.Array('gtxn_ApplicationID', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_OnCompletion = z3.Array('gtxn_OnCompletion', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_NumAppArgs = z3.Array('gtxn_NumAppArgs', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_NumAccounts = z3.Array('gtxn_NumAccounts', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_AssetSender = z3.Array('gtxn_AssetSender', z3.BitVecSort(64), z3.StringSort())
gtxn_AssetReceiver = z3.Array('gtxn_AssetReceiver', z3.BitVecSort(64), z3.StringSort())
gtxn_AssetCloseTo = z3.Array('gtxn_AssetCloseTo', z3.BitVecSort(64), z3.StringSort())
gtxn_ApprovalProgram = z3.Array('gtxn_ApprovalProgram', z3.BitVecSort(64), z3.StringSort())
gtxn_ClearStateProgram = z3.Array('gtxn_ClearStateProgram', z3.BitVecSort(64), z3.StringSort())
gtxn_RekeyTo = z3.Array('gtxn_RekeyTo', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAsset = z3.Array('gtxn_ConfigAsset', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ConfigAssetTotal = z3.Array('gtxn_ConfigAssetTotal', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ConfigAssetDecimals = z3.Array('gtxn_ConfigAssetDecimals', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ConfigAssetDefaultFrozen = z3.Array('gtxn_ConfigAssetDefaultFrozen', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_FreezeAsset = z3.Array('gtxn_FreezeAsset', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_FreezeAssetAccount = z3.Array('gtxn_FreezeAssetAccount', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_FreezeAssetFrozen = z3.Array('gtxn_FreezeAssetFrozen', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_NumAssets = z3.Array('gtxn_NumAssets', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_NumApplications = z3.Array('gtxn_NumApplications', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_GlobalNumUint = z3.Array('gtxn_GlobalNumUint', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_GlobalNumByteSlice = z3.Array('gtxn_GlobalNumByteSlice', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_LocalNumUint = z3.Array('gtxn_LocalNumUint', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_LocalNumByteSlice = z3.Array('gtxn_LocalNumByteSlice', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ExtraProgramPages = z3.Array('gtxn_ExtraProgramPages', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_Nonparticipation = z3.Array('gtxn_Nonparticipation', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_ConfigAssetUnitName = z3.Array('gtxn_ConfigAssetUnitName', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetName = z3.Array('gtxn_ConfigAssetName', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetURL = z3.Array('gtxn_ConfigAssetURL', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetMetadataHash = z3.Array('gtxn_ConfigAssetMetadataHash', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetManager = z3.Array('gtxn_ConfigAssetManager', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetReserve = z3.Array('gtxn_ConfigAssetReserve', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetFreeze = z3.Array('gtxn_ConfigAssetFreeze', z3.BitVecSort(64), z3.StringSort())
gtxn_ConfigAssetClawback = z3.Array('gtxn_ConfigAssetClawback', z3.BitVecSort(64), z3.StringSort())
gtxn_Logs = z3.Array('gtxn_Logs', z3.BitVecSort(64), z3.StringSort())
gtxn_NumLogs = z3.Array('gtxn_NumLogs', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_CreatedAssetID = z3.Array('gtxn_CreatedAssetID', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_CreatedApplicationID = z3.Array('gtxn_CreatedApplicationID', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_LastLog = z3.Array('gtxn_LastLog', z3.BitVecSort(64), z3.StringSort())
gtxn_StateProofPK = z3.Array('gtxn_StateProofPK', z3.BitVecSort(64), z3.StringSort())
gtxn_NumApprovalProgramPages = z3.Array('gtxn_NumApprovalProgramPages', z3.BitVecSort(64), z3.BitVecSort(64))
gtxn_NumClearStateProgramPages = z3.Array('gtxn_NumClearStateProgramPages', z3.BitVecSort(64), z3.BitVecSort(64))


# gtxnsa_handle gtxnas_handle gtxnsas_handle
gtxna_ApplicationArgs = z3.Array('gtxna_ApplicationArgs', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()))
gtxna_Applications = z3.Array('gtxna_Applications', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))
gtxna_Assets = z3.Array('gtxna_Assets', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))
gtxna_Accounts = z3.Array('gtxna_Accounts', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()))
gtxna_Logs = z3.Array('gtxna_Logs', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()))
gtxna_ApprovalProgramPages = z3.Array('gtxna_ApprovalProgramPages', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()))
gtxna_ClearStateProgramPages = z3.Array('gtxna_ClearStateProgramPages', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.StringSort()))

# balance_handle
asset_holding_balance_uint = z3.Array('asset_holding_balance_uint', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))
asset_holding_balance_bytes = z3.Array('asset_holding_balance_bytes', z3.StringSort(), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))
asset_holding_frozen_uint = z3.Array('asset_holding_frozen_uint', z3.BitVecSort(64), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))
asset_holding_frozen_bytes = z3.Array('asset_holding_frozen_bytes', z3.StringSort(), z3.ArraySort(z3.BitVecSort(64), z3.BitVecSort(64)))

AcctAuthAddr_array_bytes = z3.Array('AcctAuthAddr_array_bytes', z3.StringSort(), z3.StringSort())


def select_2D_array(array, param1, param2):
    return array[param1][param2]

def select_3D_array(array, param1, param2, param3):
    return array[param1][param2][param3]

def store_2D_array(array, param1, param2, value):
    return z3.Store(array, param1, z3.Store(array[param1], param2, value) )
    
def try_define(internal_dict, configuration):
    if internal_dict["parameters"]["array"] == "global_state":
        op1 = internal_dict["parameters"]["op1"]
        if z3.is_bv_value(z3.simplify( z3.Select(configuration.global_state_return_uint, op1) )):
            Define(internal_dict, "uint", configuration)
        elif z3.is_string_value(z3.simplify( z3.Select(configuration.global_state_return_bytes, op1) )):
            Define(internal_dict, "bytes", configuration)

def Define(internal_dict, type, configuration):
    if type != "uint" and type != "bytes":
        log.critical("Unrecognized definition type")
        exit(runtime.UNRECOGNISED_DEFINITION_TYPE)
    internal_dict["type"] = type
    if internal_dict["parameters"]["array"] == "global_scratch_space":
        op1 = internal_dict["parameters"]["op1"]
        op2 = internal_dict["parameters"]["op2"]
        if type == "uint":
            internal_dict["value"] = select_2D_array(global_scratch_space_return_uint, op1, op2)
        elif type == "bytes":
            internal_dict["value"] = select_2D_array(global_scratch_space_return_bytes, op1, op2)
    elif internal_dict["parameters"]["array"] == "global_state":
        op1 = internal_dict["parameters"]["op1"]
        if type == "uint":
            internal_dict["value"] = z3.Select(configuration.global_state_return_uint, op1)
        elif type == "bytes":
            internal_dict["value"] = z3.Select(configuration.global_state_return_bytes, op1)
    elif internal_dict["parameters"]["array"] == "local_state":
        op1 = internal_dict["parameters"]["op1"]
        op1_type = internal_dict["parameters"]["op1_type"]
        op2 = internal_dict["parameters"]["op2"]
        if type == "uint":
            if op1_type == "uint":
                internal_dict["value"] = select_2D_array(configuration.local_state_uint_return_uint, op1, op2)
            elif op1_type == "bytes":
                internal_dict["value"] = select_2D_array(configuration.local_state_bytes_return_uint, op1, op2)
        elif type == "bytes":
            if op1_type == "uint":
                internal_dict["value"] = select_2D_array(configuration.local_state_uint_return_bytes, op1, op2)
            elif op1_type == "bytes":
                internal_dict["value"] = select_2D_array(configuration.local_state_bytes_return_bytes, op1, op2)
    elif internal_dict["parameters"]["array"] == "global_state_ex":
        op1 = internal_dict["parameters"]["op1"]
        op2 = internal_dict["parameters"]["op2"]
        if type == "uint":
            internal_dict["value"] = select_2D_array(global_state_ex_return_uint, op1, op2)
        elif type == "bytes":
            internal_dict["value"] = select_2D_array(global_state_ex_return_bytes, op1, op2)
    elif internal_dict["parameters"]["array"] == "scratch_space":
        op1 = internal_dict["parameters"]["op1"]
        if type == "uint":
            internal_dict["value"] = z3.Select(configuration.scratch_space_return_uint, op1)
        elif type == "bytes":
            internal_dict["value"] = z3.Select(configuration.scratch_space_return_bytes, op1)
    elif internal_dict["parameters"]["array"] == "local_state_ex":
        op1 = internal_dict["parameters"]["op1"]
        op2 = internal_dict["parameters"]["op2"]
        op2_type = internal_dict["parameters"]["op2_type"]
        op3 = internal_dict["parameters"]["op3"]
        if type == "uint":
            if op2_type == "uint":
                internal_dict["value"] = select_3D_array(local_state_ex_uint_return_uint, op1, op2, op3)
            elif op2_type == "bytes":
                internal_dict["value"] = select_3D_array(local_state_ex_bytes_return_uint, op1, op2, op3)
        elif type == "bytes":
            if op2_type == "uint":
                internal_dict["value"] = select_3D_array(local_state_ex_uint_return_bytes, op1, op2, op3)
            elif op2_type == "bytes":
                internal_dict["value"] = select_3D_array(local_state_ex_bytes_return_bytes, op1, op2, op3)
    
    internal_dict["value"] = z3.simplify(internal_dict["value"])

        