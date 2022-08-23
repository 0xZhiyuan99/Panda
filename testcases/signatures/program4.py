from pyteal import *

# 1 vulnerabilities
def logic_signature():
    tx_type_cond = Txn.type_enum() == TxnType.Payment
    fee_cond = Txn.fee() <= Int(10000)
    recv_cond = Txn.receiver() ==  Addr("B6Q6ZZOH5IOCG5PJ366WJU26L5Y2EASQK6ZIC7K6H3V62PZTG7HOW4FKAA")
    amount_cond = Txn.amount() == Int(2_000_000)

    # Combine together all of the parameter conditions
    params_conds = And(tx_type_cond,
                       fee_cond,
                       recv_cond,
                       amount_cond)
    
    close_remainder_cond = Txn.close_remainder_to() == Global.zero_address()

    program = And(params_conds,
                  close_remainder_cond)

    return compileTeal(program, Mode.Signature, version=5)
