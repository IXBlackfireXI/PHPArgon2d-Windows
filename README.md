# PHPArgon2d Extension User Manual

## General information

The PHPArgon2d extension enables the computation, verification, and update checking of Argon2d password hashes in a user-friendly manner within PHP.
It supports both versions of Argon2 while ensuring secure password hashing.
Additionally, the extension provides a low-level Argon2d function apart from the password hash functions. 
The Argon2 reference implementation's libargon2 is utilized for calculating the Argon2d hash.

## Limitations

**Due to the vulnerability of Argon2d to side channel attacks, it is not recommended to use this extension for password hashing in shared hosting.**

## System requirements

- At least PHP 7.4
- 64-Bit PHP
- [Git](https://git-scm.com/)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) (with the **Desktop development with C++** workload)

## Installation

### Step 1: Clone the PHP SDK

```bash
git clone https://github.com/php/php-sdk-binary-tools.git C:\php-sdk
```

### Step 2: Open the PHP SDK shell

```bash
cd C:\php-sdk
phpsdk-vs17-x64.bat
```

### Step 3: Build the directory tree

```bash
phpsdk_buildtree phpdev
```

### Step 4: Navigate to the build directory

```bash
cd /d C:\php-sdk\phpdev\vs17\x64
```

### Step 5: Clone PHP source

```bash
git clone https://github.com/php/php-src.git php-src
```

### Step 6: Enter the PHP source directory

```bash
cd php-src
```

### Step 7: Check out the matching PHP version

```bash
git checkout <matching tag or branch>
# Example: git checkout PHP-8.5.1
```

### Step 8: Download dependencies

```bash
phpsdk_deps --update --branch <major.minor>
# Example: phpsdk_deps --update --branch 8.5
```

### Step 9: Create the pecl directory

```bash
cd ..
mkdir pecl
```

### Step 10: Clone the PHPArgon2d extension

```bash
git clone https://github.com/IXBlackfireXI/PHPArgon2d-Windows.git C:\php-sdk\phpdev\vs17\x64\pecl\PHPArgon2d-Windows
```

### Step 11: Enter the extension directory

```bash
cd pecl\PHPArgon2d-Windows
```

### Step 12: Initialize submodules

```bash
git submodule update --init --recursive
```

### Step 13: Clone the Argon2 reference implementation

```bash
git clone https://github.com/P-H-C/phc-winner-argon2.git C:\php-sdk\phpdev\vs17\x64\pecl\phc-winner-argon2
```

### Step 14: Build the Argon2 static library

Open the **Developer Command Prompt for VS 2022**, then run:

```bash
cd C:\php-sdk\phpdev\vs17\x64\pecl\phc-winner-argon2
cl /c src\argon2.c src\core.c src\encoding.c src\opt.c src\thread.c /Iinclude
lib argon2.obj core.obj encoding.obj opt.obj thread.obj /OUT:argon2.lib
```

### Step 15: Copy the library to the deps folder

```bash
copy C:\php-sdk\phpdev\vs17\x64\pecl\phc-winner-argon2\argon2.lib C:\php-sdk\phpdev\vs17\x64\deps\lib\
```

### Step 16: Return to the PHP source directory

```bash
cd C:\php-sdk\phpdev\vs17\x64\php-src
```

### Step 17: Run buildconf

```bash
buildconf
```

### Step 18: Verify the extension is available

```bash
configure --help
# --with-argon2d "for argon2d support" should appear in the list
```

### Step 19: Configure the build

```bash
# Thread-safe build (TS)
configure --disable-all --enable-cli --with-argon2d=shared

# Non-thread-safe build (NTS)
configure --disable-all --disable-zts --enable-cli --with-argon2d=shared
```

### Step 20: Compile

```bash
nmake
```

### Step 21: Copy the extension DLL to your PHP installation

```bash
copy C:\php-sdk\phpdev\vs17\x64\php-src\x64\Release_TS\php_argon2d.dll <PHP DESTINATION FOLDER>
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
