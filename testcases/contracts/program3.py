from pyteal import *

# 1 vulnerabilities
def approval_program():
    scratchCount = ScratchVar(TealType.uint64)
    
    on_create = Seq(
        App.globalPut(Bytes("global1"), Int(100)),
        App.globalPut(Bytes("global2"), Int(200)),
        Approve(),
    )

    on_call = Seq(    
        If( App.localGet(Int(0),Bytes("local1")) > Int(50) ).Then(
            Seq(
                scratchCount.store(App.localGet(Txn.sender(), Bytes("local1"))),
                App.localPut(Int(0),Bytes("local1"),scratchCount.load() + Int(1)),
                Approve(),
            ),
        ),
        Reject(),
    )

    on_optin = Seq(
        App.localPut(Txn.sender(),Bytes("local1"),Int(100)),
        Approve(),
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.OptIn, on_optin],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.UpdateApplication, Reject()],
        [Txn.on_completion() == OnComplete.DeleteApplication, Reject()],
        [Txn.on_completion() == OnComplete.NoOp, on_call]
    )

    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)
