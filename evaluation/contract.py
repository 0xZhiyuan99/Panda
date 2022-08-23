import psycopg2
import os
import sqlite3
import re
import hashlib
import multiprocessing
import time
import sys 
sys.path.append("..")
import setting
import util

contract_table_sql = """ 
CREATE TABLE contracts (
    AppID bigint PRIMARY KEY,
    program TEXT,
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

contract_result_sql = "INSERT INTO contracts ( AppID, program, repeat_count, opcodes, opcode_kinds, run_time, leaves_number, total_path, feasible_path, arbitrary_update, arbitrary_deletion, unchecked_group_size, force_clear_state, unchecked_payment_receiver, unchecked_asset_receiver, time_stamp_dependeceny ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

def parse_data(line):
    run_time = re.search("Time: ([0-9\.]+),", line).group(1)
    leaves_number = re.search("Leaves Number: ([0-9]+),", line).group(1)
    total_path = re.search("Total Path: ([0-9]+),", line).group(1)
    feasible_path = re.search("Feasible Path: ([0-9]+)", line).group(1)
    opcodes = re.search("Opcodes: ([0-9]+)\\(([0-9]+)\\)", line)
    return run_time, leaves_number, total_path, feasible_path, opcodes.group(1), opcodes.group(2)

def evaluate_smart_contracts(appID_list, identifier):
    db_path = setting.DB_PATH + "contract_db{}.sqlite3".format(identifier)
    try:
        os.unlink(db_path)
    except:
        pass
    sqlite_connection = sqlite3.connect(db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute(contract_table_sql)

    count = 0
    total = len(appID_list)
    for item in appID_list:
        count += 1
        appID = item[0]
        approval_program = item[1]
        repeat_count = item[2]

        #print("appID: {}, process: {}/{}".format(appID, count, total))

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
        for line in os.popen("python3 ../panda.py --silent -sc -i {}".format(appID)):
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
        sqlite_cursor.execute(contract_result_sql,(appID, approval_program, repeat_count, opcodes, opcode_kinds, 
            run_time, leaves_number, total_path, feasible_path, arbitrary_update, arbitrary_deletion, unchecked_group_size, 
            force_clear_state, unchecked_payment_receiver, unchecked_asset_receiver, time_stamp_dependeceny))
        
    sqlite_connection.commit()
    sqlite_connection.close()

def deep_unique_hash(program):
    filename = util.decompile(program)
    bytecode = open(filename,'r').read()
    filter_bytecode = []
    for line in bytecode.split('\n')[3:]:
        line = line.split("//")[0] # Delete comment
        if line.startswith("pushbytes") or line.startswith("pushint"):
            line = line.split(" ")[0] # Delete data
        filter_bytecode.append(line)
    os.unlink(filename)

    return hashlib.md5("\n".join(filter_bytecode).encode('utf-8')).digest().hex()


def deep_unique_set():
    blockchain_connection = psycopg2.connect(database=setting.ALGO_DB, user=setting.ALGO_USER, password=setting.ALGO_PWD, host=setting.ALGO_HOST, port=setting.ALGO_PORT)
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()

    blockchain_cursor.execute("select DISTINCT on (params->'approv') index, params->'approv' from app where deleted=false")
    result_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    print("Distinct contracts number: {}".format(len(result_list)))

    count = 0
    total = len(result_list)

    unique_programs = {}
    for item in result_list:
        count += 1
        print("process: {}/{}".format(count, total))
        appID = item[0]
        approval_program = item[1]
        unique_programs[deep_unique_hash(approval_program)] = appID

    print("Deep unique contracts number: {}".format(len(result_list)))
    return result_list

def program_count():
    blockchain_connection = psycopg2.connect(database=setting.ALGO_DB, user=setting.ALGO_USER, password=setting.ALGO_PWD, host=setting.ALGO_HOST, port=setting.ALGO_PORT)
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()

    blockchain_cursor.execute("select params->'approv', count(params->'approv') from app where deleted=false group by params->'approv'")
    result_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    return result_list

def distinct_set():
    blockchain_connection = psycopg2.connect(database=setting.ALGO_DB, user=setting.ALGO_USER, password=setting.ALGO_PWD, host=setting.ALGO_HOST, port=setting.ALGO_PORT)
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()

    blockchain_cursor.execute("select DISTINCT on (params->'approv') params->'approv', index from app where deleted=false")
    result_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    print("Distinct contracts number: {}".format(len(result_list)))

    return result_list


def combine_database():
    final_db_path = setting.DB_PATH + "combined_contract_db.sqlite3"
    try:
        os.unlink(final_db_path)
    except:
        pass
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute(contract_table_sql)
    for db_file in os.listdir(setting.DB_PATH):
        if not db_file.startswith("contract_db"):
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

    result_list = distinct_set()
    program_count_list = program_count()
    associate_list = []
    
    for pcount in program_count_list:
        for result in result_list:
            if result[0] == pcount[0]:
                # appID program count
                associate_list.append((result[1], result[0], pcount[1]))

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

