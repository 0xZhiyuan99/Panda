from pyteal import *

# 1 vulnerabilities
def approval_program():
    on_create = Seq(
        App.globalPut(Bytes("val1"), Int(100)),
        App.globalPut(Bytes("val2"), Int(200)),
        Approve(),
    )

    on_update = Seq(
        If( App.globalGet(Bytes("val1")) < Int(30) ).Then(
            Approve(),
        ),
        Reject(),
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, Approve()],
        [Txn.on_completion() == OnComplete.NoOp, Approve()]
    )

    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)
