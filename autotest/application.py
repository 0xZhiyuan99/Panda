import random
import os

def vul_update(x,y,z):
    return """#pragma version 5
int {}
int {}
int {}
+
dup
*
+
int 3
%
bnz label_ok
txn OnCompletion
int 4
==
assert
int 1
return
label_ok:
txn OnCompletion
int 0
==
assert
int 1
return
""".format(x,y,z)

def update_case():
    x = random.randint(1,100)
    y = random.randint(1,100)
    z = random.randint(1,100)
    content = vul_update(x,y,z)
    result = ((y + z) * (y + z) + x) % 3
    if result != 0:
        vul = False
    else:
        vul = True
    return content, vul



def vul_delete(x,y,z):
    return """#pragma version 5
int {}
int {}
*
dup
+
int {}
-
int 4
%
bnz label_ok
txn OnCompletion
int 5
==
assert
int 1
return
label_ok:
txn OnCompletion
int 0
==
assert
int 1
return
""".format(y,z,x)

def delete_case():
    x = random.randint(1,10)
    y = random.randint(20,100)
    z = random.randint(20,100)
    content = vul_delete(x,y,z)
    result = ((y * z) + (y * z) - x) % 4
    if result != 0:
        vul = False
    else:
        vul = True
    return content, vul


def vul_group_size(x,y,z):
    return """#pragma version 5
byte "key"
byte "value"
app_global_put
txn OnCompletion
int 0
==
assert
int {}
int {}
*
dup
+
int {}
-
int 4
%
bnz label_ok
global GroupSize
int 10
>=
assert
int 1
return
label_ok:
global GroupSize
int 10
<=
assert
int 1
return
""".format(y,z,x)


def group_size_case():
    x = random.randint(1,10)
    y = random.randint(20,100)
    z = random.randint(20,100)
    content = vul_group_size(x,y,z)
    result = ((y * z) + (y * z) - x) % 4
    if result != 0:
        vul = False
    else:
        vul = True
    return content, vul



def vul_force_clear_state(x,y,z):
    return """#pragma version 3
txn OnCompletion
int 0
==
global GroupSize
int 10
<=
&&
assert
int {}
int {}
*
dup
+
int {}
-
int 3
%
byte "key"
byte "value"
app_local_put
int 1
return
""".format(y,z,x)


def force_clear_state_case():
    x = random.randint(1,10)
    y = random.randint(20,100)
    z = random.randint(20,100)
    content = vul_force_clear_state(x,y,z)
    result = ((y * z) + (y * z) - x) % 3
    if result == 0:
        vul = False
    else:
        vul = True
    return content, vul


def gtxn_Amount(index):
    return """
gtxn {} Amount
int 10000
>=
assert
""".format(str(index))

def gtxn_AssetAmount(index):
    return """
gtxn {} AssetAmount
int 10
>=
assert
""".format(str(index))

def gtxn_Receiver(index):
    return """
gtxn {} Receiver
global CreatorAddress
==
assert
""".format(str(index))

def gtxn_AssetReceiver(index):
    return """
gtxn {} AssetReceiver
global CreatorAddress
==
assert
""".format(str(index))


def vul_Receiver():
    content = """#pragma version 5
txn OnCompletion
int 0
==
global GroupSize
int 15
<=
&&
assert
byte "key"
byte "value"
app_global_put
"""
    txn_number = random.randint(2,15)
    vul_index = random.randint(0,txn_number-1)
    result = random.choice([True, False])
    index_list = [i for i in range(txn_number)]
    random.shuffle(index_list)

    for index in index_list:
        if result == False:
            content += gtxn_Receiver(index)
        else:
            if index != vul_index:
                content += gtxn_Receiver(index)
        content += gtxn_Amount(index)

    content += "int {}\n".format(1)
    content += "return\n"
    return content, result

def vul_AssetReceiver():
    content = """#pragma version 5
txn OnCompletion
int 0
==
global GroupSize
int 15
<=
&&
assert
byte "key"
byte "value"
app_global_put
"""
    txn_number = random.randint(2,15)
    vul_index = random.randint(0,txn_number-1)
    result = random.choice([True, False])
    index_list = [i for i in range(txn_number)]
    random.shuffle(index_list)

    for index in index_list:
        if result == False:
            content += gtxn_AssetReceiver(index)
        else:
            if index != vul_index:
                content += gtxn_AssetReceiver(index)
        content += gtxn_AssetAmount(index)

    content += "int {}\n".format(1)
    content += "return\n"
    return content, result

if __name__ == '__main__':
    path = "/home/daige/Desktop/smart-contracts/testcase.txt"
    content, vul = vul_AssetReceiver()
    test_file = open(path,"w")
    test_file.write(content)
    test_file.close()
    print(vul)
    os.system("python3 ../panda.py -sc -s {}".format(path))