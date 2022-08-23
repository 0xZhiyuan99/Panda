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



def get_app(appID):
    blockchain_connection = psycopg2.connect(database="algorand", 
                                            user="algorand", 
                                            password="algorand", 
                                            host=setting.ALGO_HOST, 
                                            port=setting.ALGO_PORT,
                                            keepalives=1,
                                            keepalives_idle=60,
                                            keepalives_interval=10,
                                            keepalives_count=15,
                                            )
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select encode(creator::bytea, 'base64'), created_at from app where index={}".format(appID))
    result = blockchain_cursor.fetchall()
    creator = result[0][0]
    created_at = result[0][1]
    blockchain_cursor.execute("select txn->'txn'->>'apap' from txn where round={} and typeenum=6 and txn->'txn'->>'snd'='{}'".format(created_at, creator))
    app_data = blockchain_cursor.fetchall()[0][0]
    blockchain_connection.close()
    return util.decompile(app_data)

def deep_unique_hash(bytecode):
    filter_bytecode = []
    for line in bytecode.split('\n'):
        line = line.split("//")[0] # Delete comment
        if line.startswith("bytecblock") or line.startswith("pushbytes"):
            line_list = [line.split(" ")[0]]
            for item in line.split(" ")[1:]:
                if len(item) != 66:
                    line_list.append(item)
            line = " ".join(line_list)
        elif line.startswith("intcblock") or line.startswith("pushint"):
            line_list = [line.split(" ")[0]]
            for item in line.split(" ")[1:]:
                if len(item) <= 6:
                    line_list.append(item)
            line = " ".join(line_list)
            
        filter_bytecode.append(line)
    result = "\n".join(filter_bytecode)
    return result, hashlib.md5(result.encode('utf-8')).digest().hex()

def include_app(file_content):
    app_index = -1
    app_id = -1

    result = re.search("gtxn ([0-9]+) ApplicationID\nintc_([0-9]).*\n==", file_content)
    if result != None:
        app_index = int(result.group(2))
    result = re.search("gtxn ([0-9]+) ApplicationID\nintc ([0-9]+).*\n==", file_content)
    if result != None:
        app_index = int(result.group(2))
        result = re.search("gtxn ([0-9]+) ApplicationID\npushint ([0-9x]+).*\n==", file_content)
    if result != None:
        try:
            app_id = int(result.group(2))
        except:
            app_id = int(result.group(2),16)

    if app_index == -1 and app_id == -1:
        return app_id, file_content
        
    if app_id == -1:
        try:
            intcblock = re.search("intcblock(.*)\n", file_content).group(1).split(" ")[1:]
            app_id = int(intcblock[app_index])
        except:
            print("Fail to parse intcblock")
            return app_id, file_content

    try:
        approval_file_name = util.get_app(app_id)
    except:
        print("Failed to fetch app: {}".format(app_id))
        return app_id, file_content
    app_content = open(approval_file_name, 'r').read()
    if not file_content.endswith("return"):
        file_content += "\nreturn"
    
    file_content = file_content.replace("label", "sig_label")
    file_content = file_content.replace("return", "bnz app_label\nerr")
    file_content += "\napp_label:\n"
    app_content = "\n".join(app_content.split("\n")[1:])
    new_content = file_content + app_content
    os.unlink(approval_file_name)

    #print("Include appID: {}".format(app_id), flush=True)
    return app_id, new_content

# PRIMARY KEY
deep_unique_set_sql = """ 
CREATE TABLE deep_unique_set (
    program TEXT PRIMARY KEY,
    unique_program TEXT,
    unique_program_hash TEXT,
    contain_app_call BOOLEAN,
    include_app bigint,
    repeat_count integer
)
"""
deep_unique_set_insert_sql = "INSERT INTO deep_unique_set ( program, unique_program, unique_program_hash, contain_app_call, include_app, repeat_count ) VALUES (?, ?, ?, ?, ?, ?)"



def contain_app_call(file_content):
    check_list = ["ApplicationID", "OnCompletion", "NumAppArgs"]
    for item in check_list:
        if item in file_content:
            return True
    return False

def get_deep_unique_set(program_list, identifier):
    db_path = setting.DB_PATH + "deep_unique_set_db{}.sqlite3".format(identifier)
    try:
        os.unlink(db_path)
    except:
        pass
    sqlite_connection = sqlite3.connect(db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute(deep_unique_set_sql)
    for item in program_list:
        try:
            program = item[0]
            repeat_count = item[1]
            filename = util.decompile(program)
            file_content = open(filename, 'r').read()
            app_id, unique_program = include_app(file_content)
            if app_id == -1:
                app_id = 0
            unique_program, unique_program_hash = deep_unique_hash(unique_program)
            os.unlink(filename)
            sqlite_cursor.execute(deep_unique_set_insert_sql,
                    (program, unique_program, unique_program_hash, contain_app_call(file_content), app_id, repeat_count))
        except:
            pass
    sqlite_connection.commit()
    sqlite_connection.close()

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
    #blockchain_cursor.execute("select txn->'lsig'->>'l', 1 from txn where txn::jsonb ? 'lsig' limit 1000")

    result_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    return result_list


def combine_database():
    final_db_path = setting.DB_PATH + "input.sqlite3"
    try:
        os.unlink(final_db_path)
    except:
        pass
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute(deep_unique_set_sql)
    for db_file in os.listdir(setting.DB_PATH):
        if not db_file.startswith("deep_unique_set_db"):
            continue
        current_db_path = setting.DB_PATH + db_file
        sqlite_connection = sqlite3.connect(current_db_path)
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute("select * from deep_unique_set")
        signature_list = sqlite_cursor.fetchall()
        sqlite_connection.close()
        for item in signature_list:
            final_sqlite_cursor.execute(deep_unique_set_insert_sql,item)
        os.unlink(current_db_path)

    final_sqlite_connection.commit()
    final_sqlite_connection.close()


def main():
    program_set = distinct_set()
    program_set_length = len(program_set)
    pool = []
    for sp in range(0,program_set_length,setting.WORKLOAD):
        separator1 = sp
        separator2 = separator1 + setting.WORKLOAD
        if separator2 > program_set_length:
            separator2 = program_set_length
        current_set = program_set[separator1:separator2]
        process = multiprocessing.Process(target=get_deep_unique_set, args=(current_set,separator1))
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


