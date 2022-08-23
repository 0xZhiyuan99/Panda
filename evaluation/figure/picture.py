import sqlite3
import matplotlib.pyplot as plt
import numpy as np
import os
import sys 
sys.path.append("../..")
import setting
import util


contract_table_sql = """ 
CREATE TABLE contracts (
    program TEXT PRIMARY KEY,
    repeat_count integer,
    opcodes integer,
    opcode_kinds integer,
    run_time float8,
    leaves_number integer,
    total_path integer,
    feasible_path integer,
    arbitrary_update BOOLEAN,
    arbitrary_deletion BOOLEAN,
    unchecked_group_size BOOLEAN,
    force_clear_state BOOLEAN,
    unchecked_payment_receiver BOOLEAN,
    unchecked_asset_receiver BOOLEAN,
    time_stamp_dependeceny BOOLEAN
)
"""



def opcode_kinds(program):
    file_name = util.decompile(program)
    file_content = open(file_name, 'r').read()
    os.unlink(file_name)

    opcodes = []
    for line in file_content.split("\n"):
        if line.startswith("#"):
            continue
        if line.startswith("label"):
            continue
        opcode = line.split(" ")[0]
        if len(opcode) > 0:
            opcodes.append(opcode)
    return len(list(set(opcodes)))


def median(x, y):
    border = sum(y)/2
    for i in range(len(y)):
        border -= y[i]
        if border < 0:
            return x[i]

def average(x, y):
    all = 0
    for i in range(len(y)):
        all += x[i] * y[i]
    return all / sum(y)

def show_opcode_kinds():
    final_db_path = "../db/combined_static_contract_db.sqlite3"
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select program, sum(repeat_count) from contracts where opcode_kinds > 0 group by opcode_kinds")
    results = final_sqlite_cursor.fetchall()
    final_sqlite_connection.commit()
    final_sqlite_connection.close()

    x = np.array([opcode_kinds(x[0]) for x in results])
    y = np.array([x[1] for x in results])
    print(len(x))
    print("---------------")
    print(median(x, y), average(x, y))
    print("---------------")
    plt.scatter(x, y, label="Application", marker="^")


    final_db_path = "../db/combined_normal_signature_db.sqlite3"
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select program, sum(repeat_count) from signatures where opcode_kinds > 0 group by opcode_kinds")
    results = final_sqlite_cursor.fetchall()
    final_sqlite_connection.commit()
    final_sqlite_connection.close()

    x = np.array([opcode_kinds(x[0]) for x in results])
    y = np.array([x[1] for x in results])
    print(len(x))
    print("---------------")
    print(median(x, y), average(x, y))
    print("---------------")
    plt.scatter(x, y, label="Smart Signature", marker="*")


    plt.yscale("log", base=10)
    plt.xlabel("Number of Distinct Opcodes")
    plt.ylabel("Number of Smart Contracts")
    plt.legend()
    plt.savefig("/home/daige/Desktop/smart-contracts/opcodes.png", bbox_inches='tight',pad_inches=0)
    plt.show()




def show_run_time(interval):
    final_db_path = "../db/combined_static_contract_db.sqlite3"
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select run_time, sum(repeat_count) from contracts where opcode_kinds > 0 group by run_time")
    results = final_sqlite_cursor.fetchall()
    #print(results)
    final_sqlite_connection.commit()
    final_sqlite_connection.close()

    run_time_list = [x[0] for x in results]
    repeat_count_list = [x[1] for x in results]

    run_time_list_new = []
    repeat_count_list_new = []

    start = 0
    current_repeat_count = 0
    for i in range(len(run_time_list)):
        if run_time_list[i] < start + interval:
            current_repeat_count += repeat_count_list[i]
        else:
            run_time_list_new.append(start + interval / 2)
            repeat_count_list_new.append(current_repeat_count)
            start += interval
            current_repeat_count = 0
    #print(repeat_count_list_new)
    plt.scatter(run_time_list_new, repeat_count_list_new, label="Application", marker="^")

    final_db_path = "../db/combined_account_signature_db.sqlite3"
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select run_time, sum(repeat_count) from signatures where opcode_kinds > 0 group by run_time")
    results = final_sqlite_cursor.fetchall()
    #print(results)
    final_sqlite_connection.commit()
    final_sqlite_connection.close()

    run_time_list = [x[0] for x in results]
    repeat_count_list = [x[1] for x in results]

    run_time_list_new = []
    repeat_count_list_new = []

    start = 0
    current_repeat_count = 0
    for i in range(len(run_time_list)):
        if run_time_list[i] < start + interval:
            current_repeat_count += repeat_count_list[i]
        else:
            run_time_list_new.append(start + interval / 2)
            repeat_count_list_new.append(current_repeat_count)
            start += interval
            current_repeat_count = 0
    #print(repeat_count_list_new)
    plt.scatter(run_time_list_new, repeat_count_list_new, label="Smart Signature", marker="*")

    plt.yscale("log", base=10)
    plt.xlabel("Analysis Time")
    plt.ylabel("Number of Smart Contracts")
    plt.legend()
    plt.savefig("/home/daige/Desktop/smart-contracts/analysis_time.png", bbox_inches='tight',pad_inches=0)
    plt.show()






if __name__ == '__main__':
    show_opcode_kinds()
    show_run_time(15)


