#!/usr/bin/env bash

host='localhost'
access_from='%'

root_user='root'
root_pw='123'
#
oauth2_db='oicp'
oauth2_user='oicp'
oauth2_pw='oicp'
oauth2_prefix='oauth_'
#
oicp_db='oicp'
oicp_user='oicp'
oicp_pw='oicp'
oicp_prefix='oicp_'

#
# Drops all databases.
#
#
function database_all_drop {
	mysql -u${root_user} -p${root_pw} -t<<EOF
	DROP DATABASE IF EXISTS ${oauth2_db};
	DROP DATABASE IF EXISTS ${oicp_db};
EOF
}

#
# Create a database for oauth2.
#
#
function database_oauth2_create {
	mysql -u${root_user} -p${root_pw} -t<<EOF
	CREATE DATABASE IF NOT EXISTS ${oauth2_db};
	USE ${oauth2_db};
	CREATE USER IF NOT EXISTS "${oauth2_user}"@"${access_from}" IDENTIFIED BY "${oauth2_pw}";

	CREATE TABLE IF NOT EXISTS ${oauth2_prefix}clients (
		client_id VARCHAR(80) NOT NULL,
		client_secret VARCHAR(80),
		redirect_uri VARCHAR(2000) NOT NULL,
		grant_types VARCHAR(80),
		scope VARCHAR(100),
		user_id VARCHAR(80),
		CONSTRAINT clients_client_id_pk PRIMARY KEY (client_id)
	);

	CREATE TABLE IF NOT EXISTS ${oauth2_prefix}access_tokens (
		access_token VARCHAR(40) NOT NULL,
		client_id VARCHAR(80) NOT NULL,
		user_id VARCHAR(255),
		expires TIMESTAMP NOT NULL,
		scope VARCHAR(2000),
		CONSTRAINT access_token_pk PRIMARY KEY (access_token)
	);

	CREATE TABLE IF NOT EXISTS ${oauth2_prefix}authorization_codes (
		authorization_code VARCHAR(40) NOT NULL,
		client_id VARCHAR(80) NOT NULL,
		user_id VARCHAR(255),
		redirect_uri VARCHAR(2000),
		expires TIMESTAMP NOT NULL,
		scope VARCHAR(2000),
		CONSTRAINT auth_code_pk PRIMARY KEY (authorization_code)
	);

	CREATE TABLE IF NOT EXISTS ${oauth2_prefix}refresh_tokens (
		refresh_token VARCHAR(40) NOT NULL,
		client_id VARCHAR(80) NOT NULL,
		user_id VARCHAR(255),
		expires TIMESTAMP NOT NULL,
		scope VARCHAR(2000),
		CONSTRAINT refresh_token_pk PRIMARY KEY (refresh_token)
	);

	#CREATE TABLE IF NOT EXISTS ${oauth2_prefix}users (
	#	username VARCHAR(255) NOT NULL,
	#	password VARCHAR(2000),
	#	first_name VARCHAR(255),
	#	last_name VARCHAR(255),
	#	CONSTRAINT username_pk PRIMARY KEY (username)
	#);
	#
	#CREATE TABLE IF NOT EXISTS ${oauth2_prefix}scopes (
	#	scope TEXT,
	#	is_default BOOLEAN
	#);

	CREATE TABLE IF NOT EXISTS ${oauth2_prefix}jwt (
		client_id VARCHAR(80) NOT NULL,
		subject VARCHAR(80),
		public_key VARCHAR(2000),
		CONSTRAINT jwt_client_id_pk PRIMARY KEY (client_id)
	);

	GRANT ALL ON ${oauth2_db}.* TO '${oauth2_user}'@'${access_from}';

	ALTER TABLE ${oauth2_prefix}authorization_codes ADD id_token VARCHAR(1000)  NULL  DEFAULT NULL;
	INSERT INTO ${oauth2_prefix}clients (client_id, client_secret, redirect_uri) VALUES ("testclient", "testpass", "http://pflaume2/oic/client/client.php");
	INSERT INTO ${oauth2_prefix}clients (client_id, client_secret, redirect_uri) VALUES ("testclient2", "testpass", "http://192.168.56.101/oic/client/client.php");
	INSERT INTO ${oauth2_prefix}clients (client_id, client_secret, redirect_uri) VALUES ("testclient3", "???", "http://oidc-client-test.pixelwoelkchen.de/index.php");
EOF
}

#
# Create a database for oicp's user system.
#
#
function database_oicp_create {
	mysql -u${root_user} -p${root_pw} -t<<EOF
	CREATE DATABASE IF NOT EXISTS ${oicp_db};
	USE ${oicp_db};
	CREATE USER IF NOT EXISTS "${oicp_user}"@"${access_from}" IDENTIFIED BY "${oicp_pw}";

	CREATE TABLE IF NOT EXISTS ${oicp_prefix}user (
		id integer unsigned auto_increment,
		user_id VARCHAR(32),
		password VARCHAR(255),
		roles VARCHAR(255),
		salt VARCHAR(255),
		enabled INTEGER(1),
		account_non_expired INTEGER(1),
		credentials_non_expired INTEGER(1),
		account_non_locked INTEGER(1),
		name VARCHAR(255),
		given_name VARCHAR(255),
		family_name VARCHAR(255),
		middle_name VARCHAR(255),
		nickname VARCHAR(255),
		preferred_username VARCHAR(255),
		profile VARCHAR(255),
		picture VARCHAR(255),
		website VARCHAR(255),
		email VARCHAR(255),
		email_verified INTEGER(1),
		gender VARCHAR(20),
		birthdate VARCHAR(10),
		zoneinfo VARCHAR(255),
		locale VARCHAR(10),
		phone_number VARCHAR(30),
		phone_number_verified INTEGER(1),
		address VARCHAR(2000),
		updated_at INTEGER,
		PRIMARY KEY (id),
		UNIQUE KEY (user_id),
		UNIQUE KEY (email)
		);

	CREATE TABLE IF NOT EXISTS ${oicp_prefix}user_clients (
		id integer unsigned,
		client VARCHAR(255),
		claims_authorized VARCHAR(1000),
		claims_denied VARCHAR(1000)
	);
	
	GRANT ALL ON ${oicp_db}.* TO '${oicp_user}'@'${access_from}';

	INSERT INTO ${oicp_prefix}user (
		user_id,
		password,
		roles,
		salt,
		enabled,
		account_non_expired,
		credentials_non_expired,
		account_non_locked,
		name,
		given_name,
		family_name,
		middle_name,
		nickname,
		email,
		email_verified,
		gender,
		birthdate
	)
	VALUES (
		"admin",
		"\$2y\$10\$3i9/lVd8UOFIJ6PAMFt8gu3/r5g0qeCJvoSlLCsvMTythye19F77a",
		"ROLE_ADMIN,ROLE_USER",
		"",
		1,
		1,
		1,
		1,
		"Admin I. Strator",
		"Admin",
		"Strator",
		"I.",
		"Wurzelmännchen",
		"admin@wichtig.de",
		1,
		"root",
		"1980-13-01"
	);
EOF
}

database_all_drop
database_oauth2_create
database_oicp_create

