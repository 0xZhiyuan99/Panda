import psycopg2
import os
import sqlite3
import multiprocessing
import time
import re
import sys 
sys.path.append("..")
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

contract_result_sql = "INSERT INTO contracts ( program, repeat_count, opcodes, opcode_kinds, run_time, leaves_number, total_path, feasible_path, arbitrary_update, arbitrary_deletion, unchecked_group_size, force_clear_state, unchecked_payment_receiver, unchecked_asset_receiver, time_stamp_dependeceny ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

def parse_data(line):
    run_time = re.search("Time: ([0-9\.]+),", line).group(1)
    leaves_number = re.search("Leaves Number: ([0-9]+),", line).group(1)
    total_path = re.search("Total Path: ([0-9]+),", line).group(1)
    feasible_path = re.search("Feasible Path: ([0-9]+)", line).group(1)
    opcodes = re.search("Opcodes: ([0-9]+)\\(([0-9]+)\\)", line)
    return run_time, leaves_number, total_path, feasible_path, opcodes.group(1), opcodes.group(2)


def distinct_set():
    blockchain_connection = psycopg2.connect(database=setting.ALGO_DB, 
                                            user=setting.ALGO_USER, 
                                            password=setting.ALGO_PWD, 
                                            host=setting.ALGO_HOST, 
                                            port=setting.ALGO_PORT,
                                            keepalives=1,
                                            keepalives_idle=60,
                                            keepalives_interval=10,
                                            keepalives_count=15,
                                            )
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select txn->'txn'->>'apap', count(txn->'txn'->>'apap') from txn where txn::jsonb->'txn' ? 'apap' group by txn->'txn'->>'apap'")

    signature_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    return signature_list


def evaluate_smart_contracts(contract_list, identifier):
    db_path = setting.DB_PATH + "static_contract_db{}.sqlite3".format(identifier)
    try:
        os.unlink(db_path)
    except:
        pass
    sqlite_connection = sqlite3.connect(db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute(contract_table_sql)

    count = 0
    for item in contract_list:
        count += 1
        approval_program = item[0]
        repeat_count = item[1]
        file_name = util.decompile(approval_program)
        #print("process: {}/{}".format(count, total))

        arbitrary_update = False
        arbitrary_deletion = False
        unchecked_group_size = False
        force_clear_state = False
        unchecked_payment_receiver = False
        unchecked_asset_receiver = False
        time_stamp_dependeceny = False
        run_time = "0"
        leaves_number = "0"
        total_path = "0"
        feasible_path = "0"
        opcodes = "0"
        opcode_kinds = "0"
        for line in os.popen("python3 ../panda.py --silent -sc -s {}".format(file_name)):
            #print(line.strip())
            if "arbitrary update" in line:
                arbitrary_update = True
            elif "arbitrary deletion" in line:
                arbitrary_deletion = True
            elif "unchecked group size" in line:
                unchecked_group_size = True
            elif "force clear state" in line:
                force_clear_state = True
            elif "unchecked payment receiver" in line:
                unchecked_payment_receiver = True
            elif "unchecked asset receiver" in line:
                unchecked_asset_receiver = True
            elif "time stamp dependeceny" in line:
                time_stamp_dependeceny = True
            elif "Done Symbolic Execution" in line:
                run_time, leaves_number, total_path, feasible_path, opcodes, opcode_kinds = parse_data(line)
        sqlite_cursor.execute(contract_result_sql,(approval_program, repeat_count, opcodes, opcode_kinds, 
            run_time, leaves_number, total_path, feasible_path, arbitrary_update, arbitrary_deletion, unchecked_group_size, 
            force_clear_state, unchecked_payment_receiver, unchecked_asset_receiver, time_stamp_dependeceny))
        os.unlink(file_name)

    
    sqlite_connection.commit()
    sqlite_connection.close()


def combine_database():
    final_db_path = setting.DB_PATH + "combined_static_contract_db.sqlite3"
    try:
        os.unlink(final_db_path)
    except:
        pass
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute(contract_table_sql)
    for db_file in os.listdir(setting.DB_PATH):
        if not db_file.startswith("static_contract_db"):
            continue
        if not db_file.endswith("sqlite3"):
            continue
        current_db_path = setting.DB_PATH + db_file
        sqlite_connection = sqlite3.connect(current_db_path)
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute("select * from contracts")
        signature_list = sqlite_cursor.fetchall()
        sqlite_connection.close()
        for item in signature_list:
            final_sqlite_cursor.execute(contract_result_sql,item)
        os.unlink(current_db_path)

    final_sqlite_connection.commit()
    final_sqlite_connection.close()

def main():
    try:
        os.unlink(setting.DB_PATH)
    except:
        pass


    associate_list = distinct_set()
    associate_list_length = len(associate_list)
    pool = []
    for sp in range(0,associate_list_length,setting.WORKLOAD):
        separator1 = sp
        separator2 = separator1 + setting.WORKLOAD
        if separator2 > associate_list_length:
            separator2 = associate_list_length
        current_set = associate_list[separator1:separator2]
        process = multiprocessing.Process(target=evaluate_smart_contracts, args=(current_set,separator1))
        pool.append(process)

    current_pool = []
    for i in range(setting.PROCESS_COUNT):
        process = pool[0]
        process.start()
        current_pool.append(process)
        pool.pop(0)

    while(len(pool) > 0):
        for process in current_pool:
            if not process.is_alive():
                if len(pool) == 0:
                    break
                current_pool.remove(process)
                new_process = pool[0]
                new_process.start()
                current_pool.append(new_process)
                pool.pop(0)
                print("POOL size:{}".format(len(pool)))
                

    flag = True
    while flag:
        flag = False
        for process in current_pool:
            if process.is_alive():
                flag = True
                break
        time.sleep(1)
    print("All task finished!")
    combine_database()



if __name__ == '__main__':
    main()

