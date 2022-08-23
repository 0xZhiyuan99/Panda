from pyteal import *

# 1 vulnerabilities
def logic_signature():
    tx_type_cond = Txn.type_enum() == TxnType.Payment
    #fee_cond = Txn.fee() <= Int(10000)
    recv_cond = Txn.receiver() ==  Addr("B6Q6ZZOH5IOCG5PJ366WJU26L5Y2EASQK6ZIC7K6H3V62PZTG7HOW4FKAA")
    amount_cond = Txn.amount() == Int(2_000_000)

    # Combine together all of the parameter conditions
    params_conds = And(tx_type_cond,
                       recv_cond,
                       amount_cond)

    first_valid_cond = Txn.first_valid() % Int(50) == Int(0)
    last_valid_cond = Txn.last_valid() == Int(50) + Txn.first_valid()

    # Base64 encoding for `passwordpasswordpasswordpassword`
    lease_cond = Txn.lease() == Bytes("base64", "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=")

    # Combine together all of the recurring conditions
    recurring_conds = And(first_valid_cond,
                          last_valid_cond,
                          lease_cond)
    
    close_remainder_cond = Txn.close_remainder_to() == Global.zero_address()
    rekey_cond = Txn.rekey_to() == Global.zero_address()

    # Combine the safety conditions
    safety_conds = And(close_remainder_cond,
                       rekey_cond)
    
    program = And(params_conds,
                  recurring_conds,
                  safety_conds)

    return compileTeal(program, Mode.Signature, version=5)
