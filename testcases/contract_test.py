import app
import os
import txn
import tempfile
from contracts import program1, program2, program3, program4, program5, program6, program7, program8, program9, program10

def check_contract(program, total, app_args=[]):
    appID = app.create_app(program, app_args=app_args)
    count = 0
    for line in os.popen("python3 ../panda.py -sc -i {}".format(appID)):
        if "Found" in line:
            count += 1
    if count == total:
        print("PASS TEST")
    else:
        print("FAILED (check_contract)")
        os.system("python3 ../panda.py -sc -i {}".format(appID))
        exit()
    return appID

def check_contract_static(program, total):
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        file_name = tmp.name
        tmp.write(program)
    count = 0

    for line in os.popen("python3 ../panda.py -sc -s {}".format(file_name)):
        if "Found" in line:
            count += 1
    if count == total:
        print("PASS TEST")
        os.unlink(file_name)
    else:
        print("FAILED (check_contract_static)")
        os.system("python3 ../panda.py -sc -s {}".format(file_name))
        os.unlink(file_name)
        exit()


def TEST1():
    print("############### TEST 1 ###############")
    print("This program inclues 2 vulnerabilities")
    check_contract_static(program1.approval_program(), 2)
    appID = check_contract(program1.approval_program(), 2)
    app.call_app("delete", appID) # exploit the vulnerability
    print("######################################\n")

def TEST2():
    print("############### TEST 2 ###############")
    print("This program inclues 0 vulnerabilities")
    check_contract_static(program2.approval_program(), 0)
    check_contract(program2.approval_program(), 0)
    print("######################################\n")

def TEST3():
    print("############### TEST 3 ###############")
    print("This program inclues 1 vulnerabilities")
    check_contract_static(program3.approval_program(), 1)
    appID = check_contract(program3.approval_program(), 1)
    sender = app.call_app("call", appID)
    local_state = txn.get_account_info(sender)["apps-local-state"][0]["key-value"]
    assert(local_state[0]["value"]["uint"] == 101) # base64("local1") = "bG9jYWwx"
    print("######################################\n")

def TEST4():
    print("############### TEST 4 ###############")
    print("This program inclues 2 vulnerabilities")
    check_contract_static(program4.approval_program(), 2)
    check_contract(program4.approval_program(), 2)
    print("######################################\n")

def TEST5():
    print("############### TEST 5 ###############")
    print("This program inclues 1 vulnerabilities")
    check_contract_static(program5.approval_program(), 1)
    check_contract(program5.approval_program(), 1)
    print("######################################\n")

def TEST6():
    print("############### TEST 6 ###############")
    print("This program inclues 1 vulnerabilities")
    check_contract_static(program6.approval_program(), 1)
    check_contract(program6.approval_program(), 1)
    print("######################################\n")

def TEST7():
    print("############### TEST 7 ###############")
    print("This program inclues 3 vulnerabilities")
    check_contract_static(program7.approval_program(), 3)
    app_args = [str(i) * 8 for i in range(1,9)]
    check_contract(program7.approval_program(), 3, app_args=app_args)
    print("######################################\n")

def TEST8():
    print("############### TEST 8 ###############")
    print("This program inclues 4 vulnerabilities")
    check_contract_static(program8.approval_program(), 4)
    app_args = [str(i) * 8 for i in range(1,9)]
    check_contract(program8.approval_program(), 4, app_args=app_args)
    print("######################################\n")

def TEST9():
    print("############### TEST 9 ###############")
    print("This program inclues 2 vulnerabilities")
    check_contract_static(program9.approval_program(), 2)
    app_args = [str(i) * 8 for i in range(1,9)]
    check_contract(program9.approval_program(), 2, app_args=app_args)
    print("######################################\n")

def TEST10():
    print("############### TEST 10 ###############")
    print("This program inclues 1 vulnerabilities")
    check_contract_static(program10.approval_program(), 2)
    appID = check_contract(program10.approval_program(), 1)
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
    main()