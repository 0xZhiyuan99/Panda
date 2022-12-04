import setting
import psycopg2
import base64
import subprocess
import shlex
import os
import tempfile
import runtime
import logging
import z3
from urllib.error import URLError
from algosdk.error import AlgodHTTPError
from algosdk.future import transaction
from algosdk.encoding import decode_address, future_msgpack_decode

log = logging.getLogger(__name__)


def Uint(value):
    uint_dict = {
        "type": "uint",
        "value": value
    }
    return uint_dict

def Bytes(value):
    bytes_dict = {
        "type": "bytes",
        "value": value
    }
    return bytes_dict

def Undefined(parameters):
    tbd_dict = {
        "type": "undefined",
        "value": None,
        "parameters": parameters,
    }
    return tbd_dict

def deepcopy(input):
    output = {}
    for key in input:
        if isinstance(input[key], list):
            output[key] = list(input[key])
        elif isinstance(input[key], dict):
            output[key] = deepcopy(input[key])
        else:
            output[key] = input[key]
    return output

def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    shell = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return shell.communicate()[0].decode('utf-8', 'strict')

# Decompile the bytecodes into TEAL program
def decompile(bytecodes):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        file_name = tmp.name
        tmp.write(base64.b64decode(bytecodes))
    teal_program = run_command("goal clerk compile -D {}".format(file_name))
    with open(file_name, "w") as tmp:
        tmp.write(teal_program)
    return file_name

def get_app(appID):
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
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select encode(creator::bytea, 'base64'), created_at from app where index={}".format(appID))
    result = blockchain_cursor.fetchall()
    creator = result[0][0]
    created_at = result[0][1]
    blockchain_cursor.execute("select txn->'txn'->>'apap' from txn where round={} and typeenum=6 and txn->'txn'->>'snd'='{}'".format(created_at, creator))
    app_data = blockchain_cursor.fetchall()[0][0]
    blockchain_connection.close()
    return decompile(app_data)

# Use the Algorand SDK to obtain application info
def read_app_info(app_id, force = True):
    global_state = {}
    try:
        app_info = setting.algod_client.application_info(app_id)
    except URLError:
        log.error("Connect to algod server failed")
        exit(runtime.CONNECT_TO_ALGOD_SERVER_FAILED)
    except AlgodHTTPError:
        if force == False:
            log.info("App ID does not exists")
            return None, None
        else:
            log.error("App ID does not exists")
            exit(runtime.CONNECT_TO_ALGOD_SERVER_FAILED)
    app_state = app_info['params']['global-state'] if "global-state" in app_info['params'] else []
    approval_program = app_info['params']['approval-program']
    for item in app_state:
        item_key = item['key']
        item_value = item['value']
        global_value = {}
        if item_value['type'] == 1: # bytes type
            global_value["type"] = "bytes"
            global_value["value"] = z3.StringVal( base64.b64decode(item_value['bytes']).decode("Latin-1") )
        else: # uint type
            global_value["type"] = "uint"
            global_value["value"] = z3.BitVecVal( item_value['uint'], 64 )
        formatted_key = base64.b64decode(item_key).decode("Latin-1")
        global_state[formatted_key] = global_value
    return decompile(approval_program), global_state


def get_lsig_address(teal_program):
    try:
        response = setting.algod_client.compile(teal_program)
        programstr = response['result']
        program = base64.decodebytes(programstr.encode())
        lsig = transaction.LogicSig(program)
        return decode_address(lsig.address()).decode("Latin-1")
    except:
        return "\x00" * 32

if __name__ == '__main__':
    app_info = setting.algod_client.asset_info(150)
    #approval_file_name, global_state = read_app_info(233725848)
    #print(approval_file_name)
    #print(global_state)


# tealer ./input.txt --print-cfg; dot -Tps cfg.dot -o cfg.ps
# tealer /tmp/tmp0dchkt56; dot -Tps can_delete_1.dot -o can_delete_1.ps

# python3 ./panda.py -lsig -s test2.teal

