import psycopg2
import os
import sqlite3
import re
import hashlib
import tempfile
import sys 
sys.path.append("..")
import setting
import util


def main():
    final_db_path = setting.DB_PATH + "combined_signature_db.sqlite3"
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select program from signatures where contain_app_call=1")
    results = final_sqlite_cursor.fetchall()
    total = len(results)
    count = 0

    for item in results:
        program = item[0]
        file_name = util.decompile(program)
        file_content = open(file_name, 'r').read()

        app_index = -1
        app_id = -1
        result = re.search("ApplicationID\nintc_([0-9]).*\n==", file_content)
        if result != None:
            app_index = int(result.group(1))
        result = re.search("ApplicationID\nintc ([0-9]+).*\n==", file_content)
        if result != None:
            app_index = int(result.group(1))
        result = re.search("ApplicationID\npushint ([0-9]+).*\n==", file_content)
        if result != None:
            app_id = int(result.group(1))

        if app_index == -1 and app_id == -1:
            print("Failed: {}",format(file_name))
            exit()
        
        if app_id == -1:
            intcblock = re.search("intcblock(.*)\n", file_content).group(1).split(" ")[1:]
            app_id = int(intcblock[app_index])


        try:
            setting.algod_client.application_info(app_id)
        except:
            print("app does not exists: {}".format(app_id))

        
        os.unlink(file_name)
        count += 1
        print("process: {}/{}".format(count,total))
        
    final_sqlite_connection.close()


def main2():
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
    blockchain_cursor.execute("select index, encode(creator::bytea, 'base64'), created_at from app")
    app_list = blockchain_cursor.fetchall()
    for item in app_list:
        appID = item[0]
        creator = item[1]
        created_at = item[2]
        blockchain_cursor.execute("select txn->'txn'->>'apap' from txn where round={} and typeenum=6 and txn->'txn'->>'snd'='{}'".format(created_at, creator))
        app_data = blockchain_cursor.fetchall()
        print(app_data)

    blockchain_connection.close()

def main3():
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
    blockchain_cursor.execute("select count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig';")
    result = blockchain_cursor.fetchall()
    print(result)
    blockchain_connection.close()

def attack():
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
    blockchain_cursor.execute("select txn->'txn'->>'snd', txn->'txn'->>'apid' from txn where (txn::jsonb->'txn'->>'apan')::integer=5")
    attack_list = blockchain_cursor.fetchall()
    print("Fetch attack list successfully")
    count = 0
    for item in attack_list:
        sender = item[0]
        appID = item[1]
        blockchain_cursor.execute("select encode(creator::bytea, 'base64') from app where index={}".format(appID))
        app_data = blockchain_cursor.fetchall()
        if len(app_data) == 0:
            continue
        creator = app_data[0][0]
        if creator != sender:
            count += 1
    print(len(attack_list), count)
    blockchain_connection.close()



def opcode_kinds(db_name, table, condition=""):
    final_db_path = setting.DB_PATH + db_name
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()
    final_sqlite_cursor.execute("select program, repeat_count from {} where opcode_kinds=0 {}".format(table, condition))
    results = final_sqlite_cursor.fetchall()
    total = len(results)
    count = 0

    version6 = 0
    version6_sum = 0
    for item in results:
        count += 1
        program = item[0]
        file_name = util.decompile(program)
        file_content = open(file_name, 'r').read()
        os.unlink(file_name)

        for line in file_content.split("\n"):
            if line.startswith("#"):
                version = int(line.split(" ")[2])
                if version == 6:
                    version6 += 1
                    version6_sum += int(item[1])
                break
    
    final_sqlite_connection.close()
    print(version6, version6_sum)



   
if __name__ == '__main__':
    opcode_kinds("combined_signature_db.sqlite3", "signatures", "and contain_app_call=0")
    opcode_kinds("combined_signature_db.sqlite3", "signatures", "and contain_app_call=1")
    opcode_kinds("combined_static_contract_db.sqlite3", "contracts")
    opcode_kinds("combined_contract_db.sqlite3", "contracts")


