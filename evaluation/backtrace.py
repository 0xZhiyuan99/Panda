import os

backtrace = "(2-7)->(8-11)->(466-475)"





def main():
    input_file = "/home/daige/Desktop/smart-contracts/output.txt"
    output_file = "/home/daige/Desktop/smart-contracts/backtrace.txt"
    f = open(output_file, "w")
    bytecodes = open(input_file, 'r').read().split('\n')
    block = backtrace.split("->")
    for i in range(len(block)):
        current_block = block[i]
        start_line = int(current_block.split('-')[0][1:])
        end_line = int(current_block.split('-')[1][:-1])
        #print(start_line, end_line)
        try:
            if bytecodes[start_line-2].startswith("label"):
                start_line -= 1
            if bytecodes[start_line-2].startswith("sig_label"):
                start_line -= 1
            if bytecodes[start_line-2].startswith("app_label"):
                start_line -= 1
        except:
            pass
        for line in range(start_line-1, end_line):
            f.write(bytecodes[line] + "\n")
        f.write("\n\n")
    f.close()





if __name__ == '__main__':
    main()