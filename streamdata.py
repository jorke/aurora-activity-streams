import boto3
import sys
import json
import base64
import zlib
import uuid


from opensearchpy import OpenSearch, RequestsHttpConnection

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType


enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms_client = boto3.client('kms')

search = OpenSearch(
    hosts = [{'host': "localhost", 'port': 9200}],
    # http_auth = auth,
    # use_ssl = True,
    # verify_certs = True,
    connection_class = RequestsHttpConnection
)
INDEX = 'aurora-pgsql-das-index'


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

def decrypt(file, key_id):
    with open(file) as f:
        line_data = f.readlines()
        for l in line_data:
            d = json.loads(l)
            payload = base64.b64decode(d['databaseActivityEvents'])
            data_key = base64.b64decode(d['key'])
            # print(record_key)
            # print(blob)
            data_key_decrypt_result = kms_client.decrypt(CiphertextBlob=data_key, EncryptionContext={'aws:rds:dbc-id': "cluster-753QANBMP5KBJZOKGK76IZWZRE"})['Plaintext']
            print(data_key_decrypt_result)

            decrypted = zlib.decompress(decrypt_payload(payload, data_key_decrypt_result),zlib.MAX_WBITS + 16) 
            # decrypted = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
            # return decrypted
            print(decrypted)
            events = json.loads(decrypted)
            # x = kms_client.decrypt(
            #     # KeyId=key, 
            #     EncryptionContext={ "aws:rds:db-id": "cluster-753QANBMP5KBJZOKGK76IZWZRE" },CiphertextBlob=key)
            # payload_data = kms_client.decrypt(CiphertextBlob=payload, KeyId=key_id, EncryptionContext={'aws:rds:dbc-id': "cluster-753QANBMP5KBJZOKGK76IZWZRE"})
            # text = kms_client.decrypt(KeyId=key_id, CiphertextBlob=blob)['Plaintext']
            # key = kms_client.decrypt(KeyId=key_id, CiphertextBlob=blob)['Plaintext']
            # print(payload_data)
            ## Filtering logic. ## Removes heartbeat and rdsadmin events
            for dbEvent in events['databaseActivityEventList'][:]:
                if dbEvent['type'] == "heartbeat" or (dbEvent['dbUserName'] and dbEvent["dbUserName"] == "rdsadmin"):
                    events['databaseActivityEventList'].remove(dbEvent)
            

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
                    search.index(index=INDEX, 
                                #  doc_type="_doc", 
                                 id=uuid.uuid4(), body=index_body)

#   payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
#         data_key_decoded = base64.b64decode(record_data['key'])
#         data_key_decrypt_result = kms.decrypt(CiphertextBlob=data_key_decoded, EncryptionContext={'aws:rds:dbc-id': RESOURCE_ID})
#         plaintext = decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext'])
#         events = json.loads(plaintext)


#text = self.kms_client.decrypt(KeyId=key_id, CiphertextBlob=cipher_text)['Plaintext']
if __name__ == "__main__":
   file = sys.argv[1]
   key_id = sys.argv[2]
   decrypt(file, key_id)
