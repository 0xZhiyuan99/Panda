import random
import os

def gtxn_CloseRemainderTo(index):
    return """
gtxn {} CloseRemainderTo
global ZeroAddress
==
assert
""".format(str(index))

def gtxn_AssetCloseTo(index):
    return """
gtxn {} AssetCloseTo
global ZeroAddress
==
assert
""".format(str(index))

def gtxn_RekeyTo(index):
    return """
gtxn {} RekeyTo
global ZeroAddress
==
assert
""".format(str(index))

def gtxn_Fee(index):
    return """
gtxn {} Fee
int 1000
==
assert
""".format(str(index))


def groupSize(size):
    return """
global GroupSize
int {}
==
assert
""".format(size)


def safe_case():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size)
    for index in index_list:
        content += gtxn_CloseRemainderTo(index)
        content += gtxn_AssetCloseTo(index)
        content += gtxn_RekeyTo(index)
        content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content
    

def vul_group_size():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size + 1)
    for index in index_list:
        content += gtxn_CloseRemainderTo(index)
        content += gtxn_AssetCloseTo(index)
        content += gtxn_RekeyTo(index)
        content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content

def vul_CloseRemainderTo():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    vul_index = random.randint(0,group_size-1)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size)
    for index in index_list:
        if index != vul_index:
            content += gtxn_CloseRemainderTo(index)
        content += gtxn_AssetCloseTo(index)
        content += gtxn_RekeyTo(index)
        content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content


def vul_AssetCloseTo():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    vul_index = random.randint(0,group_size-1)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size)
    for index in index_list:
        content += gtxn_CloseRemainderTo(index)
        if index != vul_index:
            content += gtxn_AssetCloseTo(index)
        content += gtxn_RekeyTo(index)
        content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content


def vul_RekeyTo():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    vul_index = random.randint(0,group_size-1)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size)
    for index in index_list:
        content += gtxn_CloseRemainderTo(index)
        content += gtxn_AssetCloseTo(index)
        if index != vul_index:
            content += gtxn_RekeyTo(index)
        content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content


def vul_Fee():
    content = "#pragma version 5\n"
    group_size = random.randint(1,15)
    vul_index = random.randint(0,group_size-1)
    index_list = [i for i in range(group_size)]
    random.shuffle(index_list)

    content += groupSize(group_size)
    for index in index_list:
        content += gtxn_CloseRemainderTo(index)
        content += gtxn_AssetCloseTo(index)
        content += gtxn_RekeyTo(index)
        if index != vul_index:
            content += gtxn_Fee(index)
    content += "int {}\n".format(group_size + 1)
    content += "return\n"
    return content


if __name__ == '__main__':
    for i in range(10):
        path = "/home/daige/Desktop/smart-contracts/testcase.txt"
        test_file = open(path,"w")
        test_file.write(safe_case())
        test_file.close()
        os.system("python3 ../panda.py -lsig -s {}".format(path))