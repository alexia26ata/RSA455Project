from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidKey

def test_encryption_limit(key_size):
    print(f"\nTesting with {key_size}-bit key:")
    
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    
    # Test the user's specific string
    user_string = "Jnjnjnjnjnjnjnjnjnjnjjnckjdefncklenfjdncjdncjdnciimkedmxeomeokemwcklmewcklmewlkcmlwemclwemclwkmclwfirjfirjfirjfirjowkdoiwejoisjwdcmlw"
    print(f"\nTesting user's string length: {len(user_string)} characters")
    try:
        # Try to encrypt
        ciphertext = public_key.encrypt(
            user_string.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Success: Can encrypt user's string of {len(user_string)} characters")
        
        # Try to decrypt to verify
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        if plaintext.decode('utf-8') == user_string:
            print("Verification: Successful decryption")
    except ValueError as e:
        print(f"Failed with user's string: {str(e)}")
    except Exception as e:
        print(f"Error with user's string: {str(e)}")
    
    # Now test increasing lengths
    lengths_to_test = [100, 120, 128, 140, 150, 160, 170, 180, 190, 200]
    
    last_success = 0
    
    for length in lengths_to_test:
        test_message = 'A' * length
        print(f"\nTesting message length: {length} characters")
        
        try:
            # Try to encrypt
            ciphertext = public_key.encrypt(
                test_message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Success: Can encrypt {length} characters")
            last_success = length
            
            # Try to decrypt to verify
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if plaintext.decode('utf-8') == test_message:
                print("Verification: Successful decryption")
            
        except ValueError as e:
            print(f"Failed: {str(e)}")
            print(f"Maximum successful length: {last_success} characters")
            break
            
        except Exception as e:
            print(f"Error: {str(e)}")
            print(f"Maximum successful length: {last_success} characters")
            break

print("Starting encryption limit tests...")
test_encryption_limit(1024)
test_encryption_limit(2048) 