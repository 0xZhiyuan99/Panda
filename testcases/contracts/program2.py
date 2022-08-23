from pyteal import *

# 0 vulnerabilities
def approval_program():
    on_create = Seq(
        App.globalPut(Bytes("seller_key"), Global.zero_address()),
        Approve(),
    )

    on_delete = Seq(
        If( Global.latest_timestamp() < Int(1234567890) ).Then(
            Seq(
                Assert(
                    Or(
                        Txn.sender() == App.globalGet(Bytes("seller_key")),
                        Txn.sender() == Global.creator_address(),
                    )
                ),
                Approve(),
            )
        ),
        Reject(),
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.OptIn, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.UpdateApplication, Reject()],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
        [Txn.on_completion() == OnComplete.NoOp, Approve()]
    )

    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)
