import runtime
import setting
import z3
import registry
import logging

log = logging.getLogger(__name__)

registry_list = [
    ("smart signature", registry.unchecked_transaction_fee_in_lsig, "Found unchecked transaction fees!"),
    ("smart signature", registry.unchecked_RekeyTo_in_lsig, "Found unchecked rekey-to parameters!"),
    ("smart signature", registry.unchecked_CloseRemainderTo_in_lsig, "Found unchecked close-remainder-to parameters!"),
    ("smart signature", registry.unchecked_AssetCloseTo_in_lsig, "Found unchecked asset-close-to parameters!"),
    ("smart contract", registry.arbitrary_update_vulnerability, "Found an arbitrary update vulnerability!"),
    ("smart contract", registry.arbitrary_delete_vulnerability, "Found an arbitrary deletion vulnerability!"),
    ("smart contract", registry.unchecked_group_size_vulnerability, "Found an unchecked group size vulnerability!"),
    ("smart contract", registry.force_clear_state_vulnerability, "Found a force clear state vulnerability!"),
    ("smart contract", registry.unchecked_payment_receiver_vulnerability, "Found an unchecked payment receiver vulnerability!"),
    ("smart contract", registry.unchecked_asset_receiver_vulnerability, "Found an unchecked asset receiver vulnerability!"),
    ("smart contract", registry.time_stamp_dependeceny_vulnerability, "Found a time stamp dependeceny vulnerability!"),
]

# Make sure the correct registry table is loaded!
registry_list = [
    ("smart signature", registry.unchecked_transaction_fee_in_lsig2, "Found unchecked transaction fees!"),
    ("smart signature", registry.unchecked_RekeyTo_in_lsig2, "Found unchecked rekey-to parameters!"),
    ("smart signature", registry.unchecked_CloseRemainderTo_in_lsig2, "Found unchecked close-remainder-to parameters!"),
    ("smart signature", registry.unchecked_AssetCloseTo_in_lsig2, "Found unchecked asset-close-to parameters!"),
    ("smart contract", registry.arbitrary_update_vulnerability, "Found an arbitrary update vulnerability!"),
    ("smart contract", registry.arbitrary_delete_vulnerability, "Found an arbitrary deletion vulnerability!"),
    ("smart contract", registry.unchecked_group_size_vulnerability, "Found an unchecked group size vulnerability!"),
    ("smart contract", registry.force_clear_state_vulnerability, "Found a force clear state vulnerability!"),
    ("smart contract", registry.unchecked_payment_receiver_vulnerability, "Found an unchecked payment receiver vulnerability!"),
    ("smart contract", registry.unchecked_asset_receiver_vulnerability, "Found an unchecked asset receiver vulnerability!"),
    ("smart contract", registry.time_stamp_dependeceny_vulnerability, "Found a time stamp dependeceny vulnerability!"),
]

vulnerability_record = []
message_record = []
backtrace_record = []

def run(configuration):
    #runtime.solver.display()

    constraints = runtime.solver.get_constraints()
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
    analyzer = z3.Solver()
    analyzer.set("timeout", 10000)
    analyzer.add( z3.Int("x") * z3.Int("x") * z3.Int("x") - z3.Int("y") * z3.Int("y") + z3.Int("x") == 7975971701) 
    analyzer.add( z3.Int("x") > 1990) # Speed up solving!
    analyzer.add( z3.Int("x") < 2000)
    print(analyzer.check())  # unknown !!!
    
