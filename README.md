# YAOCO-OpenID-Connect-Provider

A basic PHP OpenID Connect Provider.

This is based on the great [OAuth2.0 Server](https://bshaffer.github.io/oauth2-server-php-docs/) by bshaffer.

## First Steps

### 1. Check out the code

```bash
# create a directory for your great project
cd mycoolserver
# get the source code
git clone https://github.com/eikekuehn/YAOCO-OpenID-Connect-Provider
# install dependencies
./composer.phar install
```

### 2. Setup a database

Configure `setup_db.sh` to suit your needs. The user `root_user` must have the priviliges to create new users and grant them rights.

At the moment this script is very simple it drops existing databases with that name and creates new ones. So be careful. There be dragons!
    
### 3. Generate new keys

You need to generate a set of keys for the server to use. In addition you will need a JWKS file. On how to obtain those I found some useful information here: [OADA/rsa-pem-to-jwk](https://github.com/OADA/rsa-pem-to-jwk).

### 4. Setup your server

If you are using Apache2 you need to enable `mod_rewrite` and `AllowOveride All` in your `sites-available/xxx-yoursite.conf`config. At the moment the server is easiest to set up if you point the root of your server to the `web/` directory of your project.

### 5. Go and provide some identities ;)

You should be all set up now. If you find run into errors go ahead and fix them (or report them to me ;) ). Same applies to this documentation which will - with your help - improve over time.
