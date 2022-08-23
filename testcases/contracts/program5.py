from pyteal import *

# 1 vulnerabilities
def approval_program():
    
    on_create = Seq(
        Approve(),
    )

    index = Txn.group_index() - Int(1)
    on_call = Seq(
        App.globalPut(Bytes("val1"), Int(100)),
        Assert(
            And(
                Gtxn[index].type_enum() == TxnType.Payment,
                Gtxn[index].sender() == Txn.sender(),
                #Gtxn[index].receiver() == Global.current_application_address(),
                Gtxn[index].amount() >= Global.min_txn_fee(),
                Global.group_size() == Int(2),
            )
        ),
        Approve(),
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.OptIn, Reject()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.UpdateApplication, Reject()],
        [Txn.on_completion() == OnComplete.DeleteApplication, Reject()],
        [Txn.on_completion() == OnComplete.NoOp, on_call]
    )

    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)
