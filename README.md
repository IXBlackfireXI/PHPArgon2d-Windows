# PHPArgon2d Extension User Manual

## General information

The PHPArgon2d extension enables the computation, verification, and update checking of Argon2d password hashes in a user-friendly manner within PHP.
It supports both versions of Argon2 while ensuring secure password hashing.
Additionally, the extension provides a low-level Argon2d function apart from the password hash functions. 
The Argon2 reference implementation's libargon2 is utilized for calculating the Argon2d hash..

## Limitations

**Due to the vulnerability of Argon2d to side channel attacks, it is not recommended to use this extension for password hashing in shared hosting.**

## System requirements

- At least PHP 7.4
- 64-Bit PHP


## Installation

```bash
# Step 1: Download the PHPArgon2d extension
git clone --recursive https://github.com/Identeco/PHPArgon2d.git
cd PHPArgon2d

# Step 2: Build the static libargon2.a library from the reference implementation 
cd ext/argon2
CFLAGS="-fPIC" make
rm libargon2.so.1
cd ../..

# Step 3: Build the PHPArgon2d extension and test it
phpize
./configure --with-argon2d
make
make test

# Step 4: Install the extension
make install
echo "extension=argon2d.so" > php.ini
```

## Usage

### Constants
The following constants can be passed:

```php
VERSION_13 # Use version 1.3 of Argon2d
VERSION_10 # Use version 1.0 of Argon2d
DEFAULT_VALUE # Use the default values 
```

### Generation of a password hash

The *argon2d_password_hash()* method is a high-level function that can be used to calculate secure Argon2d password hashes. 
Parameters can be selected to fit the user's needs, but any use of unsafe values (see [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)) will result in an exception.
The resulting hash is returned in PHC string format.

```php
argon2d_password_hash(String $password, int $memory = 65536, int $iterations = 3, int $parallelism = 4, int $version = 0x13): String
```

### Verification of a password hash

The *argon2d_password_hash_verify()* method is a high-level function that checks whether a given Argon2d password hash in PHC string format matches a given password. 
This function does not support Argon2d password hashes in PHC string format with secret keys or associated data. 
The return value is a Boolean corresponding to the result of the check.
If an error occurs, an exception is thrown.

```php
argon2d_password_hash_verify(String $password_hash, String $password): Bool
```

### Checking whether a password hash needs to be updated

The *argon2d_password_hash_need_rehash()* method is a high-level function to check if a given Argon2d password hash in a PHC string format needs to be updated. 
A hash needs to be updated if the parameters in the password hash are less than the passed parameters, or if insecure parameters are used. 
This function does not support Argon2d password hashes in PHC string format with secret keys or associated data. 
The return value is a Boolean corresponding to the result of the check.


```php
argon2d_password_hash_need_rehash(String $password_hash, int $memory = 65536, int $iterations = 3, int $parallelism = 4, int $version = 0x13): Bool
```

### Low-Level Function 
The *argon2d_raw_hash()* method is a low-level function that computes an Argon2d hash. 
All parameters are flexible as long as they are within the allowed value range (see [Argon2-RFC 9106](https://dl.acm.org/doi/pdf/10.17487/RFC9106)). 
If insecure parameters are used (see [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)), an **E_NOTICE** is raised.
The hash is returned in decimal encoding.
If an error occurs, an exception is thrown.

```php
argon2d_raw_hash(String $password, String $salt, int $memory = 65536, int $iterations = 3,  int $parallelism = 4, int $tag_length = 32, int $version = 0x13, String $secret_key = NULL, String $assoziated_data): String
```

### Example for Password Hashing 
The following example code shows how to implement user authentication in PHP using the PHPArgon2d extension:

```php
public function register_user(String $password, String $username):String
{
    try{
        // Calculate the password hash for the given password with the default cost parameters 
        $password_hash = argon2d_password_hash($password);
    }
    catch(Exceprion $e){
        // An error occurred while calculating the hash, which must now be handled
    }

    // Stores the password hash in the database
    $db.store($password_hash, $username)
}
```

```php
public function check_credentials(String $password, String $username):bool
{
    // Get the user's stored password hash from the database
    $password_hash = db.getPasswordHash($username);

    try{
        // Check if the passed password matches the given password hash
        if(argon2d_password_hash_verify($password_hash, $password)){

            // Check if the stored password hash needs to be updated due to updated cost parameters 
            if(argon2d_password_hash_need_rehash($password_hash)){

                // Calculates a new password hash with the updated cost parameters 
                $new_password_hash = argon2d_password_hash($password);

                // Stores the new password hash in the database
                $db.store($new_password_hash, $username)
            }

            // Credentials correct 
            return true;
        }

        // Credentials incorrect
        return false;
    }
    catch(Exception $e){
        // An error has occurred during the verification or calculation of the hash, which must now be handled
    }
}
```

### Example for the Identeco Credential Check  
The following example code shows how the PHPArgon2d extension can be used to calculate the Argon2d hash of the user name for the [Identeco Credential Check](https://identeco.de/de/products/credential-check/).

```php
// Disables warning due to low cost parameters when calculating an Argon2d hash
error_reporting(E_ALL & ~E_NOTICE);

public function get_argon2d_username(String $username):String
{
    try{
        // Calculate the Argon2d hash of the username with a static salt and given cost parameters 
        return argon2d_raw_hash($username, "StaticSalt", 512, 1, 1, 16);
    }
    catch(Exceprion $e){
        // An error occurred while calculating the hash, which must now be handled
    }
}
```
