import base64
from algosdk.future import transaction
from algosdk import account
from algosdk.logic import get_application_address
from txn import fund_account, generate_new_account_with_algo
import sys 
sys.path.append("..")
import setting

# helper function to compile program source
def compile_program(source_code):
    compile_response = setting.algod_client.compile(source_code)
    return base64.b64decode(compile_response['result'])

# helper function that formats global state for printing
def format_state(state):
    formatted = {}
    for item in state:
        key = item['key']
        value = item['value']
        formatted_key = base64.b64decode(key).decode("Latin-1")
        if value['type'] == 1:
            formatted[formatted_key] = base64.b64decode(value['bytes']).decode("Latin-1")
        else:
            formatted[formatted_key] = value['uint']
    return formatted

# helper function to read app global state
def read_global_state(app_id):
    app = setting.algod_client.application_info(app_id)
    global_state = app['params']['global-state'] if "global-state" in app['params'] else []
    return format_state(global_state)


# create new application
def create_app(approval_program, app_args=[]):

    clear_program = "#pragma version 5\nerr\nint 0\nreturn"

    approval_program = compile_program(approval_program)
    clear_program = compile_program(clear_program)

    # Use a new address to deploy the smart contract
    owner_private_key, address1 = generate_new_account_with_algo()

    local_ints = 5
    local_bytes = 5
    global_ints = 10
    global_bytes = 10
    global_schema = transaction.StateSchema(global_ints, global_bytes)
    local_schema = transaction.StateSchema(local_ints, local_bytes)

    # define sender as creator
    sender = account.address_from_private_key(owner_private_key)

    # declare on_complete as NoOp
    on_complete = transaction.OnComplete.NoOpOC.real

    # get node suggested parameters
    params = setting.algod_client.suggested_params()

    # create unsigned transaction
    txn = transaction.ApplicationCreateTxn(sender, params, on_complete, \
                                            approval_program, clear_program, \
                                            global_schema, local_schema, app_args=app_args,)

    # sign transaction
    signed_txn = txn.sign(owner_private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    setting.algod_client.send_transactions([signed_txn])

    # await confirmation
    transaction.wait_for_confirmation(setting.algod_client, tx_id, 5)

    # display results
    transaction_response = setting.algod_client.pending_transaction_info(tx_id)
    app_id = transaction_response['application-index']
    appAddr = get_application_address(app_id)
    fund_account(appAddr)
    print("Created new app-id:", app_id)

    return app_id


# call application
def call_app(method, app_id, app_args=None, foreign_apps=None):

    # Use a new address to deploy the smart contract
    caller_private_key, address1 = generate_new_account_with_algo()
    
    # declare sender
    sender = account.address_from_private_key(caller_private_key)

    # get node suggested parameters
    params = setting.algod_client.suggested_params()

    if method == "call":
        txn = transaction.ApplicationNoOpTxn(sender, params, app_id, app_args, foreign_apps)
    elif method == "delete":
        txn = transaction.ApplicationDeleteTxn(sender, params, app_id)
    elif method == "update":
        txn = transaction.ApplicationUpdateTxn(sender, params, app_id)

    elif method == "optout":
        txn = transaction.ApplicationCloseOutTxn(sender, params, app_id)
    elif method == "clear":
        txn = transaction.ApplicationClearStateTxn(sender, params, app_id)
    else:
        print("Unrecognised application call method!")
        exit()

    # Opt in first
    optin_txn = transaction.ApplicationOptInTxn(sender, params, app_id)
    signed_optin_txn = optin_txn.sign(caller_private_key)
    tx_id = signed_optin_txn.transaction.get_txid()
    setting.algod_client.send_transactions([signed_optin_txn])
    transaction.wait_for_confirmation(setting.algod_client, tx_id, 5)

    # Send the application call transaction
    signed_txn = txn.sign(caller_private_key)
    tx_id = signed_txn.transaction.get_txid()
    setting.algod_client.send_transactions([signed_txn])
    transaction.wait_for_confirmation(setting.algod_client, tx_id, 5)

    return sender


def call_app_with_txn(method, app_id, app_args=None, foreign_apps=None):

    # Use two different addresses
    txn_sender_private_key, address2 = generate_new_account_with_algo()
    caller_private_key, address1 = generate_new_account_with_algo()
    
    # declare sender
    txn_sender = account.address_from_private_key(txn_sender_private_key)
    caller = account.address_from_private_key(caller_private_key)

    # get node suggested parameters
    params = setting.algod_client.suggested_params()

    if method == "call":
        callTxn = transaction.ApplicationNoOpTxn(caller, params, app_id, app_args, foreign_apps)
    elif method == "delete":
        callTxn = transaction.ApplicationDeleteTxn(caller, params, app_id)
    elif method == "update":
        txn = transaction.ApplicationUpdateTxn(caller, params, app_id)
    elif method == "optin":
        callTxn = transaction.ApplicationOptInTxn(caller, params, app_id)
    elif method == "optout":
        callTxn = transaction.ApplicationCloseOutTxn(caller, params, app_id)
    elif method == "clear":
        callTxn = transaction.ApplicationClearStateTxn(caller, params, app_id)

    appAddr = get_application_address(app_id)
    payTxn = transaction.PaymentTxn(txn_sender, params, appAddr, 10000000, None, "Group Payment")
    transaction.assign_group_id([payTxn, callTxn])

    # sign transaction
    signed_callTxn = callTxn.sign(caller_private_key)   
    signed_payTxn = payTxn.sign(txn_sender_private_key)

    # send transaction
    setting.algod_client.send_transactions([signed_payTxn, signed_callTxn])

    tx_id = signed_callTxn.transaction.get_txid()
    
    # await confirmation
    transaction.wait_for_confirmation(setting.algod_client, tx_id, 10)
    #print("{} contract with payment successfully!".format(method))

