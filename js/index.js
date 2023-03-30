const AWS = require('aws-sdk');
const kms = new AWS.KMS({region: 'us-west-2'});
const RESOURCE_ID = process.env.RESOURCE_ID
const { unzip } = require('node:zlib');

const {
    buildClient,
    CommitmentPolicy,
    RawAesKeyringNode,
    RawAesWrappingSuiteIdentifier,
} = require('@aws-crypto/client-node')

const { decrypt } = buildClient( CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT )
    
exports.handler = async (event) => {
    event.records.map(async (record) => {
        const payload_decoded = Buffer.from(data.databaseActivityEvents, 'base64')
        const data_key_decoded = Buffer.from(data.key, 'base64')
        
        const data_key_decrypt_result = await kms.decrypt({
            CiphertextBlob: data_key_decoded, 
            EncryptionContext: { "aws:rds:dbc-id": RESOURCE_ID }
        }).promise()

        const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING;
        const unencryptedMasterKey = new Uint8Array(data_key_decrypt_result.Plaintext);

        const keyring = new RawAesKeyringNode({
            keyName: "DataKey",
            keyNamespace: "BC",
            wrappingSuite: wrappingSuite,
            unencryptedMasterKey: unencryptedMasterKey,
            
        });

        const { plaintext, messageHeader } = await decrypt(keyring, data.databaseActivityEvents, { encoding: 'base64'})

        unzip(plaintext, (err, buffer) => {
            if (err) {
            console.error('An error occurred:', err);
            process.exitCode = 1;
            }
            console.log(buffer.toString())
            return { records: buffer.toString() };
        });
    }
}
