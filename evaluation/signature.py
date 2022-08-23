import psycopg2
import os
import sqlite3
import multiprocessing
import time
import re
import hashlib
import sys 
sys.path.append("..")
import setting
import util


signature_table_sql = """ 
CREATE TABLE signatures (
    program TEXT PRIMARY KEY,
    contain_app_call BOOLEAN,
    include_app bigint,
    repeat_count integer,
    opcodes integer,
    opcode_kinds integer,
    run_time float8,
    leaves_number integer,
    total_path integer,
    feasible_path integer,
    unchecked_transaction_fees BOOLEAN,
    unchecked_rekey_to BOOLEAN,
    unchecked_close_remainder_to BOOLEAN,
    unchecked_asset_close_to BOOLEAN
)
"""

signature_result_sql = "INSERT INTO signatures ( program, contain_app_call, include_app, repeat_count, opcodes, opcode_kinds, run_time, leaves_number, total_path, feasible_path, unchecked_transaction_fees, unchecked_rekey_to, unchecked_close_remainder_to, unchecked_asset_close_to ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

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
    blockchain_cursor.execute("select txn->'lsig'->>'l', count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig' group by txn->'lsig'->>'l'")

    signature_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    return signature_list

    print("signature_list: {}".format(len(signature_list)))
    print("OK")
    sqlite_connection = sqlite3.connect(setting.DB_PATH + "backup.sqlite3")
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute("select program from signatures")
    program_list = sqlite_cursor.fetchall()
    sqlite_connection.close()

    program_dict = {}
    for program in program_list:
        program_dict[program[0]] = 1
    print("program_dict: {}".format(len(program_dict)))

    item_dict = {}
    for item in signature_list:
        item_dict[item[0]] = item
    print("item_dict: {}".format(len(item_dict)))

    count = 0
    for program in program_list:
        if program[0] in item_dict.keys():
            item_dict[program[0]] = None
            count += 1
        else:
            print(program[0])
            exit()
    print("count: {}".format(count))

    results = []
    for key in item_dict.keys():
        if item_dict[key] != None:
            results.append(item_dict[key])

    print("results: {}".format(len(results)))
    return results


def deep_unique_set():
    current_db_path = setting.DB_PATH + "input.sqlite3"
    sqlite_connection = sqlite3.connect(current_db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute("SELECT program, SUM(repeat_count) FROM deep_unique_set group by unique_program_hash")
    signature_list = sqlite_cursor.fetchall()
    sqlite_connection.close()
    return signature_list


def combine_database():
    final_db_path = setting.DB_PATH + "combined_signature_db.sqlite3"
    try:
        os.unlink(final_db_path)
    except:
        pass
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute(signature_table_sql)
    count = 0
    for db_file in os.listdir(setting.DB_PATH):
        if not db_file.startswith("signature_db"):
            continue
        try:
            current_db_path = setting.DB_PATH + db_file
            sqlite_connection = sqlite3.connect(current_db_path)
            sqlite_cursor = sqlite_connection.cursor()
            sqlite_cursor.execute("select * from signatures")
            signature_list = sqlite_cursor.fetchall()
            sqlite_connection.close()
            for item in signature_list:
                final_sqlite_cursor.execute(signature_result_sql,item)
        except:
            count += 1
        os.unlink(current_db_path)
    
    print("Failed: {}".format(count))
    final_sqlite_connection.commit()
    final_sqlite_connection.close()


def contain_app_call(file_content):
    check_list = ["ApplicationID", "OnCompletion", "NumAppArgs"]
    for item in check_list:
        if item in file_content:
            return True
    return False


def evaluate_smart_signatures(signature_list, identifier):
    db_path = setting.DB_PATH + "signature_db{}.sqlite3".format(identifier)
    try:
        os.unlink(db_path)
    except:
        pass
    sqlite_connection = sqlite3.connect(db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute(signature_table_sql)

    count = 0
    for item in signature_list:
        count += 1
        signature = item[0]
        repeat_count = item[1]
        file_name = util.decompile(signature)
        file_content = open(file_name, 'r').read()
        #print("process: {}/{}".format(count, total))
        unchecked_transaction_fees = False
        unchecked_rekey_to = False
        unchecked_close_remainder_to = False
        unchecked_asset_close_to = False
        include_app = 0
        run_time = "0"
        leaves_number = "0"
        total_path = "0"
        feasible_path = "0"
        opcodes = "0"
        opcode_kinds = "0"
        for line in os.popen("python3 ../panda.py -lsig --silent -ia -s {}".format(file_name)):
            if "unchecked transaction fees" in line:
                unchecked_transaction_fees = True
            elif "unchecked rekey-to" in line:
                unchecked_rekey_to = True
            elif "unchecked close-remainder-to" in line:
                unchecked_close_remainder_to = True
            elif "unchecked asset-close-to" in line:
                unchecked_asset_close_to = True
            elif "Include appID" in line:
                include_app = int(line.strip().split("Include appID: ")[1])
            elif "Done Symbolic Execution" in line:
                run_time, leaves_number, total_path, feasible_path, opcodes, opcode_kinds = parse_data(line)
        sqlite_cursor.execute(signature_result_sql,(signature, contain_app_call(file_content),include_app, repeat_count,
                opcodes, opcode_kinds, run_time, leaves_number, total_path, feasible_path, unchecked_transaction_fees, 
                unchecked_rekey_to, unchecked_close_remainder_to, unchecked_asset_close_to))
        os.unlink(file_name)

    sqlite_connection.commit()
    sqlite_connection.close()


def main():
    signature_set = distinct_set()
    signature_set_length = len(signature_set)
    pool = []
    for sp in range(0,signature_set_length,setting.WORKLOAD):
        separator1 = sp
        separator2 = separator1 + setting.WORKLOAD
        if separator2 > signature_set_length:
            separator2 = signature_set_length
        current_set = signature_set[separator1:separator2]
        process = multiprocessing.Process(target=evaluate_smart_signatures, args=(current_set,separator1))
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

