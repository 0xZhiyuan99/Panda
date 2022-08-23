import os
import sys 
sys.path.append("..")
import util

def main():
    input_file = "/home/daige/Desktop/smart-contracts/input.txt"
    output_dir = "/home/daige/Desktop/smart-contracts/"
    bytecodes = open(input_file, 'r').read()
    file_name = util.decompile(bytecodes)

    os.system("mv {} {}/output.txt".format(file_name, output_dir))
    os.system("python3 ../panda.py -sc -s {}output.txt".format(output_dir))
    os.chdir(output_dir)
    os.system("tealer output.txt --print-cfg")
    os.system("dot -Tps cfg.dot -o cfg.ps")
    os.unlink("cfg.dot")


def main2():
    input_file = "/home/daige/Desktop/smart-contracts/input.txt"
    output_dir = "/home/daige/Desktop/smart-contracts/"
    bytecodes = open(input_file, 'r').read()
    file_name = util.decompile(bytecodes)

    os.system("mv {} {}/output.txt".format(file_name, output_dir))
    for line in os.popen("python3 ../panda.py -lsig -ia -s {}output.txt".format(output_dir)):
        if line.startswith("Recombined File:"):
            combined_file_path = line.split("Recombined File:")[1].strip()
        print(line.strip())

    os.chdir(output_dir)
    os.system("cp {} {}/output.txt".format(combined_file_path, output_dir))
    cmd = "tealer {} --print-cfg".format(combined_file_path)
    os.system(cmd)
    os.system("dot -Tps cfg.dot -o cfg.ps")
    os.unlink("cfg.dot")

def main3():
    input_file = "/home/daige/Desktop/smart-contracts/input.txt"
    output_dir = "/home/daige/Desktop/smart-contracts/"
    bytecodes = open(input_file, 'r').read()
    file_name = util.decompile(bytecodes)

    os.system("mv {} {}/output.txt".format(file_name, output_dir))
    for line in os.popen("python3 ../panda.py -lsig -s {}output.txt".format(output_dir)):
        print(line.strip())

    os.chdir(output_dir)
    cmd = "tealer {}/output.txt --print-cfg".format(output_dir)
    os.system(cmd)
    os.system("dot -Tps cfg.dot -o cfg.ps")
    os.unlink("cfg.dot")


def main4():
    input_file = "/home/daige/Desktop/smart-contracts/input.txt"
    output_dir = "/home/daige/Desktop/smart-contracts/"
    appID = open(input_file, 'r').read()
    file_name, global_state = util.read_app_info(appID)

    os.system("mv {} {}/output.txt".format(file_name, output_dir))
    os.system("python3 ../panda.py -sc -i {}".format(appID))
    os.chdir(output_dir)
    os.system("tealer output.txt --print-cfg")
    os.system("dot -Tps cfg.dot -o cfg.ps")
    os.unlink("cfg.dot")

if __name__ == '__main__':
    main2()

