<?php
namespace YAOCO;

use OAuth2\Storage\UserCredentialsInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

class UserManager implements UserProviderInterface, UserCredentialsInterface
{
	/**
	 * Connection to the database.
	 *
	 * @var Doctrine\DBAL\Connection
	 */
	private $connection;

	/**
	 * Encoder used to encode passwords.
	 *
	 * @var Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder
	 */
	private $encoder;

	/**
	 * String to prefix database tablenames with.
	 *
	 * @var string
	 */
	private $prefix = 'oicp_';

	/**
	 * Constructor.
	 *
	 * @param Doctrine\DBAL\Connection $connection connection to the database
	 * @param Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder $encoder encoder used for passwords
	 * @return void
	 */
	public function __construct( \Doctrine\DBAL\Connection $connection, \Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder $encoder ) {
		$this->connection = $connection;
		$this->encoder = $encoder;
	}

	/**
	 * Loads a user from the database and stores the information in an object.
	 * 
	 * If no user with the given name exists an userobject with an anonymous user
	 * is returned.
	 *
	 * To check if an actual user is logged in call
	 * YAOCO\User::isLoggedIn( ).
	 *
	 * @param $username
	 * @return YAOCO\User
	 */
	public function loadUserByUsername( $username ) {
		// the default will be an anonymous user
		// status: not logged in
		$status = false;
		$clients = array( );
		$data = array(
			'user_id' => 'anon.',
			'password' => '',
			'roles' => array( ),
			'salt' => ''
		);

		// if we are told to return the anonymous user we don't have to do anything
		// further
		if ( $username !== 'anon.' ) {
			// try to load the requested user
			$stmt = $this->connection->executeQuery( 'SELECT * FROM ' . $this->prefix . 'user WHERE user_id = ?', array( $username ) );

			if ( $rawData = $stmt->fetch( ) ) {
				$data = $rawData;
				// the user existst

				// fetch the clients
				$stmt = $this->connection->executeQuery( 'SELECT * FROM ' . $this->prefix . 'user_clients WHERE id = ?', array( $data[ 'id' ] ) );
				// and create an array of claims granted or denied by the user
				while ( $row = $stmt->fetch( ) ) {
					$clients[ $row [ 'client' ] ][ 'authorized' ] = explode( ' ', $row[ 'claims_authorized' ] );
					$clients[ $row [ 'client' ] ][ 'denied' ] = explode( ' ', $row[ 'claims_denied' ] );
				}

				// some data has to be converted
				$data[ 'email_verified' ] = ( $data[ 'email_verified' ] == 1 );
				$data[ 'phone_number_verified' ] = ( $data[ 'phone_number_verified' ] == 1 );
				$data[ 'updated_at' ] = date( \DateTime::RFC3339, $data[ 'updated_at' ] );
				$data[ 'salt' ] = ( $data[ 'salt' ] === '' ) ? null : $data[ 'salt' ]; 
				$data[ 'roles' ] = explode( ',', $data[ 'roles' ] ); 
				// the address will be a JSON string
				// @todo decide what to to with the address JSON object
				$data[ 'address' ] = ( $data[ 'address' ] );
				// mark the user as logged in
				$status = true;
			} else {
				// the user does not exist
				// @todo decide whether to throw an exception
				//throw new UsernameNotFoundException( sprintf( 'Username "%s" does not exist.', $username ) );
				// mark the user as not existent
				$status = null;
			}
		}

		// create the new user
		$user = new User( $data[ 'user_id' ], $data[ 'password' ], $data[ 'roles' ], true, true, true, true );
		$user->initiate( $data, $clients, $status );
		return $user;
	}

	/**
	 * Resets the user object to what is stored in the database.
	 *
	 * @param UserInterface $user the user to refresh
	 * @return YAOCO\User
	 */
	public function refreshUser( UserInterface $user ) {
		if ( ! $user instanceof User ) {
			throw new UnsupportedUserException( sprintf( 'Instances of "%s" are not supported.', get_class( $user ) ) );
		}

		return $this->loadUserByUsername( $user->getClaim( 'user_id' ) );
	}

	/**
	 * Marks this this class as the provider for YAOCO\User.
	 *
	 * @param string $class the name of the class this provider handles
	 * @return bool
	 */
	public function supportsClass( $class ) {
		return $class === 'YAOCO\User';
	}

	/**
	 * Functions not defined by UserProviderInterface
	 */

	/**
	 * Updates an user entry in the database.
	 *
	 * @param array $data the userdata array keys equal field names
	 * @param array $clients clients as keys holding an array of granted claims
	 * @return bool true on success
	 */
	private function updateUserEntry( array $data, array $clients ) {
		// convert some data if it is set
		if ( isset( $data[ 'email_verified' ] ) )
			$data[ 'email_verified' ] = ( $data[ 'email_verified' ] ) ? 1 : 0 ;
		if ( isset( $data[ 'phone_number_verified' ] ) )
			$data[ 'phone_number_verified' ] = ( $data[ 'phone_number_verified' ] ) ? 1 : 0 ;
		if ( isset( $data[ 'salt' ] ) )
			$data[ 'salt' ] = ( $data[ 'salt' ] === null ) ? '' : $data[ 'salt' ];
		if ( isset( $data[ 'roles' ] ) )
			$data[ 'roles' ] = implode( ',', $data[ 'roles' ] );
		if ( isset( $data[ 'address' ] ) )
			// @todo decide what to to with the address JSON object
			$data[ 'address' ] = ( $data[ 'address' ] );

		$data[ 'updated_at' ] = time( );
		// update the user data
		$affectedRows = $this->connection->update(
			$this->prefix . 'user',
			$data,
			array(
				'id' => $data[ 'id' ]
			)
		);

		if ( $affectedRows === 0 ) {
			// the user does not seem to exist
			return false;
		}

		// update the clients
		// @todo find some more elegant way to update the clients

		// loop over each client
		foreach ( $clients as $client => $claims ) {
			// delete the entry if it exists
			$affectedRows += $this->connection->delete(
				$this->prefix . 'user_clients',
				array(
					'id' => $data[ 'id' ],
					'client' => $client
				)
			);
			// and insert the current state
			$affectedRows += $this->connection->insert(
				$this->prefix . 'user_clients',
				array(
					'id' => $data[ 'id' ],
					'client' => $client,
					'claims_authorized' => implode( ' ', $claims[ 'authorized' ] ),
					'claims_denied' => implode( ' ', $claims[ 'denied' ] )
				)
			);
		}

		return ( $affectedRows > 0 );
	}

	/**
	 * Save the current state of an existing user.
	 *
	 * @param YAOCO\User $user the modified user-object
	 * @return bool true on success
	 */
	public function saveUser( User $user ) {
		if ( ! $user instanceof User ) {
			throw new UnsupportedUserException( sprintf( 'Instances of "%s" are not supported.', get_class( $user ) ) );
		}

		// get the data
		list( $data, $clients ) = array_values( $user->getDataForSaving( ) );
		// update the db
		return $this->updateUserEntry( $data, $clients );
	}

	/**
	 * Create a new user from an array of data.
	 *
	 * The user's password must be raw!
	 *
	 * @param array $data the userdata array keys equal field names
	 * @param array $clients clients as keys holding an array of granted claims
	 * @return bool true on success
	 */
	public function createUser( array $data, array $clients = array( ) ) {
		// add some data if it does not exist
		$data[ 'enabled' ] = isset( $data[ 'enabled' ] ) ? $data[ 'enabled' ] : 1;
		$data[ 'account_non_locked' ] = isset( $data[ 'account_non_locked' ] ) ? $data[ 'account_non_locked' ] : 1;
		$data[ 'account_non_expired' ] = isset( $data[ 'account_non_expired' ] ) ? $data[ 'account_non_expired' ] : 1;
		$data[ 'credentials_non_expired' ] = isset( $data[ 'credentials_non_expired' ] ) ? $data[ 'credentials_non_expired' ] : 1;
		$data[ 'salt' ] = isset( $data[ 'salt' ] ) ? $data[ 'salt' ] : null;

		// insert user_id and email (unique fields) into the db
		// to check if a user with that name or email already exists
		$affectedRows = $this->connection->insert(
			$this->prefix . 'user',
			array(
				'user_id' => $data[ 'user_id' ],
				'email' => $data[ 'email' ]
			)
		);

		if ( $affectedRows === 0 ) {
			// a user with that username or email must exist
			return false;
		}

		$stmt = $this->connection->executeQuery( 'SELECT * FROM ' . $this->prefix . 'user WHERE user_id = ?', array( $data[ 'user_id' ] ) );

		if ( $newData = $stmt->fetch( ) ) {
			$data[ 'id' ] = $newData[ 'id' ];
		}

		return $this->updateUserEntry( $data, $clients );
	}

	/**
	 * Encodes the password.
	 *
	 * @param string $password the string to encode
	 * @param string $salt the salt
	 * @return string
	 */
	public function encodePassword( string $password, string $salt = null ) {
		return $this->encoder->encodePassword( $password, $salt );
	}

	/**
	 * Checks if a password is valid.
	 *
	 * @param string $passwordRaw the raw password
	 * @param string $passwordEnc encrypted password
	 * @return bool
	 */
	public function isPasswordValid( $passwordRaw, $passwordEnc ) {
		return $this->encoder->isPasswordValid( $passwordEnc, $passwordRaw, null );
	}

	/**
	 * Functions to implement OAuth2\UserCredentialsInterface
	 */

	/**
	 * Check if user credentials are valid.
	 *
	 * @param string $username the username / user_id
	 * @param string $password raw password
	 * @return bool
	 */
	public function checkUserCredentials( $username, $password ) {
		$user = $this->loadUserByUsername( $username );
		return $this->encoder->isPasswordValid( $user->getClaim( 'password' ), $password, null );
	}

	/**
	 * Get user details.
	 *
	 * Since the function must only return the user_id it does little more.
	 *
	 * @param string $username the username / user_id
	 * @return array
	 */
	public function getUserDetails( $username ) {
		$user = $this->loadUserByUsername( $username );
		return array( 'user_id' => $user->getClaim( 'user_id' ) );
	}

}
