import requests
from os import getcwd
import os
from git import Repo
import aws_encryption_sdk

# Importas necessary dependents
ver = 1.3 
# version number
keyvalue = []
# creates keyvalue variable
github_dir = "https://github.com/Dithilli/kongappend.git"
working_dir = "./testdir"



def getkey():
    key = str(input('Enter the key: '))
    value = str(input('Enter the value associated with this key: '))
    return [key,":",value]

def fileappend(appendingvalue):
    filename = os.path.join(working_dir, 'testfile.txt')
    addedkey = ""
    with open(filename, 'a') as f:
        for each in keyvalue:
            f.write(each)
            addedkey += str(each)
    return addedkey
        # if keyvalue in set(f): 
            # print("This key is already in use, please select another") 
        # else:
            # f.write(keyvalue) # consider a check to make sure that the appending value isn't already present. 
            # print("Appending your value")
            # if keyvalue in set(f):
                # print("Succsessfuly appended your value")
            # else:
                # "Appending your key value failed, please try again."



def getgitpy():
    Repo.clone_from(github_dir, working_dir)

def filecheck(checkingvalue):
    filename = "testfile.txt"
    # if file.mode =/ unfinished process for checking if the file is already open in any mode                                         
    f = open(filename, "r")
    test = f.readlines()


    url = "https://raw.github.com/Dithilli/kongappend/master/testfile.txt"
    filename = os.path.join(getcwd(), 'testfile.txt')
    print(filename)

    with requests.get(url) as r:
        with open(filename,'w+') as f:
            f.write(r.text)
            print(r.text)

def pushgit():
    pass


"""
def cycle_string(key_arn, source_plaintext, botocore_session=None): 
    Encrypts and then decrypts a string using a KMS customer master key (CMK)

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    (http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html)
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: Existing Botocore session instance
    :type botocore_session: botocore.session.Session
    

    # Create a KMS master key provider
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs['botocore_session'] = botocore_session
    master_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kms_kwargs)

    # Encrypt the plaintext source data
    ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        source=source_plaintext,
        key_provider=master_key_provider
    )
    print('Ciphertext: ', ciphertext)

    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = aws_encryption_sdk.decrypt(
        source=ciphertext,
        key_provider=master_key_provider
    )

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source
    # plaintext
    assert cycled_plaintext == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    assert all(
        pair in decrypted_header.encryption_context.items()
        for pair in encryptor_header.encryption_context.items()
    )

    print('Decrypted: ', cycled_plaintext)

"""

# actual running code

getgitpy()

print("This is the WeWork KongConfig appending App Version {} Use this app to add your environmental variable key:values to the KongConfig file.".format(ver) )

keyvalue = getkey()

addedkey = fileappend(keyvalue)

print("{} was added to the list of Key:Values".format(addedkey))