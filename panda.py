import argparse
import configparser
import setting
import logging
import symExec
import os.path
import runtime
import os
import registry
import analyzer
from algosdk.v2client import algod

log = logging.getLogger(__name__)

def check_global_parameters():
    if setting.APPLICATION_ID == 0 and setting.SOURCE_FILENAME == "":
        log.error("Missing argument '--source' or '--app-id'")
        return False
    if setting.APPLICATION_ID == 0 and (not os.path.exists(setting.SOURCE_FILENAME)):
        log.error("File {} does not exist".format(setting.SOURCE_FILENAME))
        return False
    if setting.BLOCK_SEARCH_DEPTH < 1:
        log.error("Global parameter 'BLOCK_SEARCH_DEPTH' must >= 1")
        return False
    if setting.Z3_TIMEOUT < 1:
        log.error("Global parameter 'Z3_TIMEOUT' must >= 1")
        return False
    if setting.GLOBAL_TIMEOUT < 1:
        log.error("Global parameter 'GLOBAL_TIMEOUT' must >= 1")
        return False
    if setting.APPLICATION_ID < 0:
        log.error("Global parameter 'APPLICATION_ID' must > 0")
        return False
    return True

def parse_config():
    config = configparser.ConfigParser()
    config.read("config.ini", encoding="utf-8")
    setting.algod_address = config["algod"]["algod_address"]
    setting.algod_token = config["algod"]["algod_token"]
    setting.DB_PATH = config["postgres"]["DB_PATH"]
    setting.ALGO_DB = config["postgres"]["ALGO_DB"]
    setting.ALGO_USER = config["postgres"]["ALGO_USER"]
    setting.ALGO_PWD = config["postgres"]["ALGO_PWD"]
    setting.ALGO_HOST = config["postgres"]["ALGO_HOST"]
    setting.ALGO_PORT = config["postgres"]["ALGO_PORT"]
    setting.algod_client = algod.AlgodClient(setting.algod_token, setting.algod_address)


def main():
    parse_config()

    parser = argparse.ArgumentParser()

    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-sc", "--smart-contract", action="store_true", help="The input file is a smart contract", dest="is_smart_contract")
    group1.add_argument("-lsig", "--logic-signature", action="store_true", help="The input file is a logic signature", dest="is_logic_signature")
    group1.add_argument("-aid", "--asset-id", type=int, help="The asset ID to be checked", dest="asset_id")
    group1.add_argument("-tt", "--test", action="store_true", help="Run test scripts")

    group2 = parser.add_mutually_exclusive_group(required=False)
    group2.add_argument("-s", "--source", type=str, help="Filename of the TEAL program", dest="source_filename")
    group2.add_argument("-i", "--app-id", type=int, help="App ID of the smart contract", dest="app_id")

    parser.add_argument("-ia", "--include-app", action="store_true", help="Take the signature validator into consideration", dest="include_app")
    parser.add_argument("-ls", "--load-state", action="store_true", help="Load the global state of the validator from the blockchain", dest="load_state")
    parser.add_argument("-bp", "--bypass-validator", action="store_true", help="Bypass the validator if there is no constraint on OnCompletion", dest="bypass_validator")

    parser.add_argument("-v", "--version", action="version", version="Panda version 1.0.0")
    parser.add_argument("-db", "--debug", action="store_true", help="Display debug information")
    parser.add_argument("-sl", "--silent", action="store_true", help="Do not display any information")
    parser.add_argument("-dl", "--depth-limit", type=int, help="Maximum configuration stack depth for symbolic execution", dest="block_search_depth")
    parser.add_argument("-cl", "--count-limit", type=int, help="Maximum block access count for symbolic execution", dest="block_access_count")

    parser.add_argument("-zt", "--z3-timeout", type=int, help="Timeout for Z3 (millisecond)", dest="z3_timeout")
    parser.add_argument("-gt", "--global-timeout", type=int, help="Timeout for symbolic execution (second)", dest="global_timeout")
    parser.add_argument("-rs", "--rule-set", type=str, help="The detection rule set to be used", dest="rule_set")

    args = parser.parse_args()
    if args.test == True:
        os.chdir("testcases")
        os.system("python3 ./signature_test.py")
        os.system("python3 ./contract_test.py")
        exit()

    if args.asset_id:
        analyzer.check_asset(int(args.asset_id))
        runtime.end_process()
    
    if args.include_app == True:
        if setting.IS_SMART_CONTRACT:
            log.error("Only signature mode supports the argument 'include_app'")
            exit()
        setting.INCLUDE_APP = True

    if args.load_state == True:
        if setting.IS_SMART_CONTRACT:
            log.error("Only signature mode supports the argument 'load_state'")
            exit()
        setting.LOAD_STATE = True

    if args.bypass_validator == True:
        if setting.IS_SMART_CONTRACT:
            log.error("Only signature mode supports the argument 'bypass_validator'")
            exit()
        print("Bypass validator mode enabled")
        setting.BYPASS_VALIDATOR = True

    setting.DEBUG_MODE = True if args.debug else False
    if args.is_smart_contract == True:
        setting.IS_SMART_CONTRACT = True
        setting.MAXIMUM_COST = 700
    elif args.is_logic_signature == True:
        setting.IS_LOGIC_SIGNATURE = True
        setting.MAXIMUM_COST = 20000
    
    if args.source_filename:
        setting.SOURCE_FILENAME = args.source_filename
    if args.block_search_depth:
        setting.BLOCK_SEARCH_DEPTH = args.block_search_depth
    if args.block_access_count:
        setting.BLOCK_ACCESS_COUNT = args.block_access_count
    if args.z3_timeout:
        setting.Z3_TIMEOUT = args.z3_timeout
    if args.global_timeout:
        setting.GLOBAL_TIMEOUT = args.global_timeout
    if args.app_id:
        setting.APPLICATION_ID = args.app_id
    if args.rule_set:
        setting.DETECTION_RULE_SET = args.rule_set

    if setting.DETECTION_RULE_SET == "rule1":
        import registry.rule1.signature as signature
        import registry.rule1.application as application
    elif setting.DETECTION_RULE_SET == "rule2":
        import registry.rule2.signature as signature
        import registry.rule2.application as application
    elif setting.DETECTION_RULE_SET == "rule3":
        import registry.rule3.signature as signature
        import registry.rule3.application as application
    else:
        log.critical("Unknown detection rule set")
        exit(runtime.UNKNOWN_DETECTION_RULE)
    registry.application_entry = application
    registry.signature_entry = signature
    analyzer.init_registry_list()

    print("Use detection rule set {}".format(setting.DETECTION_RULE_SET))
    runtime.solver.set("timeout", setting.Z3_TIMEOUT)
    
    logging.basicConfig()
    rootLogger = logging.getLogger(None)
    
    if setting.DEBUG_MODE:
        rootLogger.setLevel(level=logging.DEBUG)
    elif args.silent:
        rootLogger.setLevel(level=logging.CRITICAL)
    else:
        rootLogger.setLevel(level=logging.INFO)
    
    if not check_global_parameters():
        exit(runtime.INVALID_GLOBAL_PARAMETERS)

    symExec.run()

if __name__ == '__main__':
    main()

# python3 ./panda.py -sc -s test.teal
# python3 ./panda.py -sc -i 404815323
# python3 ./panda.py -lsig -ia -s test.teal
# python3 ./panda.py -lsig -s test.teal

# sudo vmhgfs-fuse .host:/ /mnt/ -o allow_other -o uid=1000

# sudo -i -u postgres
