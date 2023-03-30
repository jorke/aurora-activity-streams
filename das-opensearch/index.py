from __future__ import print_function
import json
import boto3
#boto3.set_stream_logger('',  level=10)
import base64
import zlib
import string
import random
import requests
import os
import uuid
import aws_encryption_sdk
from requests_aws4auth import AWS4Auth
from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
import datetime

REGION_NAME = os.environ['AWS_DEFAULT_REGION']
RESOURCE_ID = os.environ['resource_id']
HOST = os.environ['host']
INDEX = 'aurora-pgsql-das-index'

# def get_secret():

#     secret_name = "aurora-pgsql-das-key"

#     session = boto3.session.Session()
#     client = session.client(
#         service_name='secretsmanager',
#         region_name=REGION_NAME
#     )

#     get_secret_value_response = client.get_secret_value(
#             SecretId=secret_name)
    
#     return get_secret_value_response       

# secret_string = json.loads((get_secret()['SecretString']))

# auth = (secret_string['os.net.http.auth.user'], secret_string['os.net.http.auth.pass'])

search = OpenSearch(
    hosts = [{'host': HOST, 'port': 443}],
    # http_auth = auth,
    use_ssl = True,
    # verify_certs = True,
    connection_class = RequestsHttpConnection
)

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)

class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"
    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj
    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                        wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    def _get_raw_key(self, key_id):
        return self.wrapping_key

def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    #Decrypt the records using the master key.
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(master_key_provider=my_key_provider))
    return decrypted_plaintext

def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    #Decompress the records using zlib library.
    decrypted = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
    return decrypted


def main(event, context):

    for record in event['Records']:
        # Kinesis data is base64 encoded so decode here
        #payload = base64.b64decode(record['kinesis']['data']).decode('utf-8')
        data = base64.b64decode(record['kinesis']['data'])

        record_data = json.loads(data)
        print(record_data)
		# Decode and decrypt the payload
        payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
        data_key_decoded = base64.b64decode(record_data['key'])
        print('starting decrypt request')
        data_key_decrypt_result = kms.decrypt(CiphertextBlob=data_key_decoded, EncryptionContext={'aws:rds:dbc-id': RESOURCE_ID})
        print(data_key_decrypt_result)
        plaintext = decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext'])
        events = json.loads(plaintext)
        print(events)
        ## Filtering logic. ## Removes heartbeat and rdsadmin events
        for dbEvent in events['databaseActivityEventList'][:]:
            if dbEvent['type'] == "heartbeat" or (dbEvent['dbUserName'] and dbEvent["dbUserName"] == "rdsadmin"):
                events['databaseActivityEventList'].remove(dbEvent)
                
        ## Wrtie decrypted activities to opensearch
        ## Mapping document        
        index_mapping = {
            "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 1
                    }
                }, 
            "mappings": {
                "properties": {
                    "logTime" : {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
            "pid": {
                "type": "text"
                    },
            "dbUserName": {
                "type": "text"
                    },
            "databaseName": {
                "type": "text"
                    },
	        "command": {
                "type": "text"
                    },
            "commandText": {
                "type": "text"
		            },
            "startTime" : {
                "type": "date",
                "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    },
            "endTime" : {
                "type": "date",
                "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    }
                }
            }
        }     
        
        
        ## create mapping if index doesn't exists 
        if not search.indices.exists(INDEX):
            response = search.indices.create(INDEX, body=index_mapping)
            print("New index with mapping created")
            print(response)
        print('number of events:', len(events['databaseActivityEventList']))
        ## create a dictionary which will be send to Opensearch
        if len(events['databaseActivityEventList']) > 0:
            for dbEvent in events['databaseActivityEventList']:
                print(dbEvent)
                index_body = {}
                index_body['logTime'] = dbEvent['logTime'].split('.')[0]
                index_body['pid'] = dbEvent['pid']
                index_body['dbUserName'] = dbEvent['dbUserName']
                index_body['databaseName'] = dbEvent['databaseName']
                index_body['command'] = dbEvent['command']
                index_body['commandText'] = dbEvent['commandText']
                if 'startTime' in dbEvent:
                    index_body['startTime'] = dbEvent['startTime'].split('.')[0]
                else:
                    index_body['startTime'] = None
                if 'endTime' in dbEvent:
                    index_body['endTime'] = dbEvent['endTime'].split('.')[0]
                else:
                    index_body['endTime'] = None

                ##writes data to opensearch          
                print('writing to opensearch')
                search.index(index=INDEX, 
                    # doc_type="_doc", 
                    id=uuid.uuid4(), body=index_body)
