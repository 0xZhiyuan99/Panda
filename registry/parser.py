import z3
import runtime
import memory

# The transaction fields are specified according to the following specification.
# https://developer.algorand.org/docs/get-details/transactions/transactions/
# https://developer.algorand.org/docs/get-details/dapps/avm/teal/opcodes/#txn-f

payment_fields = ["Receiver", "Amount"]
key_registration_fields = ["VotePk", "SelectionPK", "StateProofPk", "VoteFirst", "VoteLast", "VoteKeyDilution", "Nonparticipation"]
asset_configuration_fields = ["ConfigAsset", "ConfigAssetTotal", "ConfigAssetDecimals", "ConfigAssetDefaultFrozen",
"ConfigAssetUnitName", "ConfigAssetName", "ConfigAssetURL", "ConfigAssetMetadataHash", "ConfigAssetManager",
"ConfigAssetReserve", "ConfigAssetFreeze", "ConfigAssetClawback", "CreatedAssetID"]
asset_freeze_fields = ["FreezeAsset", "FreezeAssetAccount", "FreezeAssetFrozen"]
asset_transfer_fields = ["XferAsset", "AssetAmount", "AssetSender", "AssetReceiver"]
application_call_fields = ["ApplicationID", "OnCompletion", "NumAppArgs", "NumAccounts", "ApprovalProgram", 
"ClearStateProgram", "NumAssets", "NumApplications", "GlobalNumUint", "GlobalNumByteSlice", "LocalNumUint", 
"LocalNumByteSlice", "ExtraProgramPages", "NumLogs", "CreatedApplicationID", "LastLog", 
"NumApprovalProgramPages", "NumClearStateProgramPages"]

all_txn_fields = payment_fields + key_registration_fields + asset_configuration_fields + asset_freeze_fields + asset_transfer_fields + application_call_fields


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


def is_payment_transaction(index):
    check_fields = list(set(all_txn_fields).difference(set(payment_fields)))
    for field in check_fields:
        if is_constrained_var("gtxn_{}[{}]".format(field, index)) == True:
            return False
    return True

def is_asset_transfer_transaction(index):
    check_fields = list(set(all_txn_fields).difference(set(asset_transfer_fields)))
    for field in check_fields:
        if is_constrained_var("gtxn_{}[{}]".format(field, index)) == True:
            return False
    return True

def check_txn_sender(gtxn_index_list, exclude_index):
    check_sender = []
    for index in gtxn_index_list:
        if index == exclude_index:
            continue
        check_sender.append(
            z3.Or(
                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\x00" * 32 ),
                z3.Select(memory.gtxn_Sender, index) == z3.StringVal( "\x06" * 32 )
            )
        )
        check_sender.append(
            z3.Or(
                z3.Select(memory.gtxn_AssetSender, index) == z3.StringVal( "\x00" * 32 ),
                z3.Select(memory.gtxn_AssetSender, index) == z3.StringVal( "\x06" * 32 )
            )
        )
    if runtime.solver.satisfy(check_sender) != z3.sat:
        return False
    else:
        return True