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

const data = {"type":"DatabaseActivityMonitoringRecords","version":"1.1","databaseActivityEvents":"AYABeC+alQyFbBQwjisZWWnMYSMAAAABAAJCQwAbRGF0YUtleQAAAIAAAAAMWuudKoyOs0ySHz//ADBelAhRTtUDlOtLKVsI4JxFVxJr+58fcI1gNK62Z89UIyRwKLYZVQIZOOW2uNb3wyMCAAAAAAwAABAAAAAAAAAAAAAAAAAAEkkAC0VCeZgOjMTdsx2kDv////8AAAABAAAAAAAAAAAAAAABAAAArLehJipyS/3fiXm7HS9df5+sUIsnZapBZWY5ksjO65lCJ0YI8IdRGaHb0EBG6jV+J7aJhUBIXv/99bqWu0J3jOuGeYuMWpOaOxHBSjuPsYvsd9AS9q+50MrAxclj/WWaQCIgH9S83XCApQLrQM0GOPmMFhqZ5riTSdoR74EFLcbQaex7V/Z56m+oz9ei2ZoA1K2cQgwAwCLYEhlwso5aDezn/A8O3qKLZGQXWxdrdbLdy8PYsC0zh1SWLtG4","key":"AQIDAHjQMhPzf7ht7Na5mdlcuMbHdw6MF9HouhTZ7o5co/r5MwFodkZVfuELPIisCQDdSFQvAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMwgBUeCYvj+bK5DUVAgEQgDssCD4nrBv2z0IZE/zjcgEFRf8pj3Xcc7eb4kmxqxM0+ZhAxVaXmuAr/G3YTeSZH1EzbzmRAqYVEvvVaw=="}
    
const handler = async (event) => {

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
