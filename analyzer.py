import runtime
import setting
import z3
import logging
import memory
import registry
import registry.parser

log = logging.getLogger(__name__)

registry_list = []
vulnerability_record = []
message_record = []
backtrace_record = []
vulnerable_asset_record = []
vulnerable_asset_duplicate_record = []


def init_registry_list():
    global registry_list
    registry_list = [
        ("smart signature", registry.signature_entry.unchecked_transaction_fee_in_lsig, "\033[1;33;47m[High] Found an unchecked transaction fee vulnerability"),
        ("smart signature", registry.signature_entry.unchecked_RekeyTo_in_lsig, "\033[1;31;47m[High]   Found unchecked rekey-to parameter"),
        ("smart signature", registry.signature_entry.unchecked_CloseRemainderTo_in_lsig, "\033[1;31;47m[High]   Found unchecked close-remainder-to parameter"),
        ("smart signature", registry.signature_entry.unchecked_AssetCloseTo_in_lsig, "\033[1;31;47m[High]   Found unchecked asset-close-to parameter"),
        ("smart contract", registry.application_entry.arbitrary_update_vulnerability, "\033[1;31;47m[High]   Found an arbitrary update vulnerability"),
        ("smart contract", registry.application_entry.arbitrary_delete_vulnerability, "\033[1;31;47m[High]   Found an arbitrary deletion vulnerability"),
        ("smart contract", registry.application_entry.unchecked_group_size_vulnerability, "\033[0;30;47m[Low]    Found an unchecked group size vulnerability"),
        ("smart contract", registry.application_entry.force_clear_state_vulnerability, "\033[0;30;47m[Low]    Found a force clear state vulnerability"),
        ("smart contract", registry.application_entry.unchecked_payment_receiver_vulnerability, "\033[1;31;47m[Medium]   Found an unchecked payment receiver vulnerability"),
        ("smart contract", registry.application_entry.unchecked_asset_receiver_vulnerability, "\033[1;31;47m[Medium]   Found an unchecked asset receiver vulnerability"),
        ("smart contract", registry.application_entry.time_stamp_dependeceny_vulnerability, "\033[0;30;47m[Low]    Found a time stamp dependeceny vulnerability"),
        ("smart contract", registry.application_entry.symbolic_inner_txn_fee_vulnerability, "\033[0;33;47m[Medium]    Found a symbolic inner txn fee vulnerability"),
    ]


def check_asset(asset_id):
    try:
        asset_id = int(asset_id)
    except:
        log.critical("Invalid asset ID")
        exit(runtime.INVALID_ASSET_ID)

    try:
        asset_info = setting.algod_client.asset_info(asset_id)
    except:
        log.info("Asset ID ({}) does not exist".format(asset_id))
        return

    if "clawback" in asset_info["params"] and "clawback" not in vulnerable_asset_duplicate_record:
        vulnerable_asset_record.append("\033[1;33;47m[Medium] The asset\'s clawback address is set: AssetID {:<18}".format(str(asset_id)))
        vulnerable_asset_duplicate_record.append("clawback")
    if "freeze" in asset_info["params"]and "freeze" not in vulnerable_asset_duplicate_record:
        vulnerable_asset_record.append("\033[1;33;47m[Medium] The asset\'s freeze address is set: AssetID {:<20}".format(str(asset_id)))
        vulnerable_asset_duplicate_record.append("freeze")


def vulnerable_asset(configuration):
    result = None
    gtxn_list = list(set(configuration.opcode_record["gtxn_index"]))

    for d in runtime.solver.model().decls():
        if d.name() == "gtxn_XferAsset":
            result = runtime.solver.model()[d]
            break

    if result == None:
        return
    
    for index in gtxn_list:
        if registry.parser.is_constrained_var("gtxn_XferAsset[{}]".format(index)) == True:
            
            # Make sure that the asset ID is a concrete value rather than a symbolic value
            # The number 10203040 is a randomly selected non-exists asset ID
            if runtime.solver.satisfy(z3.Select(memory.gtxn_XferAsset, index) == 10203040) == z3.unsat:
                asset_id = z3.simplify(result.__getitem__(index))
                if z3.is_bv_value(asset_id):
                    check_asset(asset_id.as_long())



def run(configuration):
    #runtime.solver.display()

    vulnerable_asset(configuration)

    #constraints = runtime.solver.get_constraints()
    for analyze_pair in registry_list:
        program_type = analyze_pair[0]
        analyze_handle = analyze_pair[1]
        message = analyze_pair[2]

        if (program_type == "smart contract" and setting.IS_SMART_CONTRACT) or \
            (program_type == "smart signature" and setting.IS_LOGIC_SIGNATURE):
            
            # Once the vulnerability is found, we do not need to check it again
            if analyze_handle not in vulnerability_record:
                flag = analyze_handle(configuration)

                if flag == True:
                    vulnerability_record.append(analyze_handle)
                    message_record.append(message)
                    backtrace = []
                    for pair in runtime.block_search_record:
                        start = runtime.instructions[pair[0]]["line_number"]
                        end = runtime.instructions[pair[1]]["line_number"]
                        backtrace.append("({}-{})".format(start,end))
                    backtrace_record.append('->'.join(backtrace))


if __name__ == '__main__':
    print("\033[0;30;47m")
    print('\033[1;31;47m[High]   Found an arbitrary update vulnerability')
    print('\033[1;31;47m[High]   Found an arbitrary deletion vulnerability')
    print('\033[1;31;47m[Medium]   Found an unchecked payment receiver vulnerability')
    print('\033[1;31;47m[Medium]   Found an unchecked asset receiver vulnerability')
    print('\033[1;31;47m[High]   Found unchecked rekey-to parameter')
    print('\033[1;31;47m[High]   Found unchecked close-remainder-to parameter')
    print('\033[1;31;47m[High]   Found unchecked asset-close-to parameter')
    print('\033[1;33;47m[High] Found an unchecked transaction fee vulnerability')
    print('\033[1;33;47m[Medium] The asset\'s clawback address is set: AssetID {: <18}'.format(123))
    print('\033[1;33;47m[Medium] The asset\'s freeze address is set: AssetID {: <20}'.format(123))
    print('\033[0;30;47m[Low]    Found an unchecked group size vulnerability')
    print('\033[0;30;47m[Low]    Found a force clear state vulnerability')
    print('\033[0;30;47m[Low]    Found a time stamp dependeceny vulnerability')
    print("\033[0;30;47m")

    exit()
    #analyzer.set("timeout", 10000)
    print( z3.simplify(z3.IntVal(2) ** z3.IntVal(64)) )
    print( z3.simplify(z3.IntVal(2) ** z3.IntVal(65)) )
    print( z3.simplify(z3.IntVal(2) ** z3.IntVal(64) == 2 ** 64) )
    print( z3.simplify(z3.IntVal(2) ** z3.IntVal(65) == 2 ** 65) )
    
    analyzer = z3.Solver()
    analyzer.push()
    analyzer.add( z3.IntVal(2) ** z3.IntVal(65) <= 2 ** 127 )
    print(analyzer.check())
    analyzer.pop()
    analyzer.add( z3.IntVal(2 ** 65) <= 2 ** 127 )
    print(analyzer.check())



