from algosdk import account
from algosdk.future import transaction
from config import funder_private_key
import sys 
sys.path.append("..")
import setting

def get_account_info(address):
    account_info = setting.algod_client.account_info(address)
    return account_info

def send_transaction(private_key, receiver, amount, note):
    sender = account.address_from_private_key(private_key)
    params = setting.algod_client.suggested_params()
    #params.flat_fee = constants.MIN_TXN_FEE 
    #params.fee = 1000

    unsigned_txn = transaction.PaymentTxn(sender, params, receiver, amount, None, note.encode())
    signed_txn = unsigned_txn.sign(private_key)
    txid = setting.algod_client.send_transaction(signed_txn)
    transaction.wait_for_confirmation(setting.algod_client, txid, 4)  

    #print("Transaction information: {}".format(json.dumps(confirmed_txn, indent=4)))

def fund_account(address):
    send_transaction(funder_private_key, address, 100000000000, "Fund")

def generate_new_account_with_algo():
    private_key, address = account.generate_account()
    fund_account(address)
    return private_key, address


if __name__ == "__main__":
    private_key, address = account.generate_account()
    print(address)
    print(private_key)



