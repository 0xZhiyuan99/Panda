import os
import tempfile
from signatures import program1, program2, program3, program4, program5, program6
from algosdk.v2client import algod
import configparser
import sys 
sys.path.append("..")
import setting

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


def check_signature(program, total):
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        file_name = tmp.name
        tmp.write(program)
    count = 0

    for line in os.popen("python3 ../panda.py -lsig -s {}".format(file_name)):
        if "Found" in line:
            count += 1
    if count == total:
        print("PASS TEST")
        os.unlink(file_name)
    else:
        print("FAILED")
        os.system("python3 ../panda.py -lsig -s {}".format(file_name))
        os.unlink(file_name)
        exit()
    

def TEST1():
    print("############### TEST 1 ###############")
    print("This program inclues 0 vulnerabilities")
    check_signature(program1.logic_signature(), 0)
    print("######################################\n")

def TEST2():
    print("############### TEST 2 ###############")
    print("This program inclues 0 vulnerabilities")
    check_signature(program2.logic_signature(), 0)
    print("######################################\n")

def TEST3():
    print("############### TEST 3 ###############")
    print("This program inclues 1 vulnerabilities")
    check_signature(program3.logic_signature(), 1)
    print("######################################\n")

def TEST4():
    print("############### TEST 4 ###############")
    print("This program inclues 1 vulnerabilities")
    check_signature(program4.logic_signature(), 1)
    print("######################################\n")

def TEST5():
    print("############### TEST 5 ###############")
    print("This program inclues 1 vulnerabilities")
    check_signature(program5.logic_signature(), 1)
    print("######################################\n")

def TEST6():
    print("############### TEST 6 ###############")
    print("This program inclues 3 vulnerabilities")
    check_signature(program6.logic_signature(), 3)
    print("######################################\n")

def TEST7():
    print("############### TEST 7 ###############")
    print("This program inclues 4 vulnerabilities")
    check_signature(open("./signatures/program7.teal", 'r').read(), 4)
    print("######################################\n")

def TEST8():
    print("############### TEST 8 ###############")
    print("This program inclues 0 vulnerabilities")
    check_signature(open("./signatures/program8.teal", 'r').read(), 0)
    print("######################################\n")

def TEST9():
    print("############### TEST 9 ###############")
    print("This program inclues 3 vulnerabilities")
    check_signature(open("./signatures/program9.teal", 'r').read(), 3)
    print("######################################\n")

def TEST10():
    print("############### TEST 10 ###############")
    print("This program inclues 1 vulnerabilities")
    check_signature(open("./signatures/program10.teal", 'r').read(), 1)
    print("######################################\n")

def main():
    TEST1()
    TEST2()
    TEST3()
    TEST4()
    TEST5()
    TEST6()
    TEST7()
    TEST8()
    TEST9()
    TEST10()


if __name__ == "__main__":
    parse_config()
    main()