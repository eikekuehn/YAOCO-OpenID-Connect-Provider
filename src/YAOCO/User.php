<?php

namespace YAOCO;

final class User extends UserSymfonyBridge {

	/**
	 * Array of clients and the claims they may or may not access.
	 *
	 * Structure:
	 * array(
	 *   'cltA' => array(
	 *     'authorized' => array( 'claim1', ... ),
	 *     'denied' => array( 'claim2', ... ),
	 *      ...
	 *   ),
	 *   ...
	 * );
	 *
	 * @var array
	 */
	private $clients = array( );

	/**
	 * Array of user data.
	 *
	 * The keys equal the database fields and the claims supported by the server.
	 *
	 * @var array
	 */
	protected $data = array( );

	/**
	 * Reflects the users status.
	 *
	 * Return values:
	 * - true: a user is logged in
	 * - false: anonymous user
	 * - null: user does not exist
	 * @var bool
	 */
	private $status;

	/**
	 * Easy method for the YAOCO\UserManager to set user data retrieved from
	 * the database.
	 *
	 * We may not override the UserSymfonyBridge::__constructor method.
	 *
	 * @param array $data the data retrieved from PREFIX_user
	 * @param array $clients the clients @see YAOCO\User::$clients
	 * @param bool $status @see YAOCO\User::$status
	 * @return void
	 */
	public function initiate( array $data, array $clients, bool $status ) {
		$this->data = $data;
		$this->clients = $clients;
		$this->status = $status;
	}

	/**
	 * Easy method for the YAOCO\UserManager to retrieve data to store it
	 * into the database.
	 *
	 * @param void
	 * @return array
	 */
	public function getDataForSaving( ) {
		return array(
			'data' => $this->data,
			'clients' => $this->clients
		);
	}

	/**
	 * Returns the requested claim.
	 *
	 * Returns null if the claim is not set.
	 * @param string $claim the claim
	 * @return mixed
	 */
	public function getClaim( string $claim ) {
		return ( isset( $this->data[ $claim ] ) ? $this->data[ $claim ] : null  );
	}

	/**
	 * Returns the requested claims if set by the user.
	 *
	 * @param array $claims an array of claims to recieve
	 * @param bool $emptyValues if true fields with null-value will be set to ''
	 * @return array
	 */
	public function getClaims( array $claims, bool $emptyValues = true ) {
		$requested = array( );
		$null = $emptyValues ? '' : null;

		foreach ( $claims as $claim ) {
			$value = $this->getClaim( $claim );
			$requested[ $claim ] = $value ? : $null;
		}

		return $requested;
	}

	/**
	 * Returns the claims the specified client might access.
	 *
	 * Claims that were denied by the client are set to null.
	 * @param string $client the id of the client
	 * @return array
	 */
	public function getClaimsForClient( string $client ) {
		if ( ! isset( $this->clients[ $client ] ) ) {
			return array( );
		}

		$authorized = $this->getClaims( $this->clients[ $client ][ 'authorized' ] );

		foreach ( $this->clients[ $client ][ 'denied' ] as $claim ) {
			$denied[ $claim ] = null;
		}

		return array_merge( $authorized, $denied );
	}

	/**
	 * Returns a list of clients authorized by the user.
	 *
	 * @param void
	 * @return array
	 */
	public function getClients( ) {
		return array_keys( $this->clients );
	}

	/**
	 * Checks if all the requested claims have been decided on
	 * (authorized or denied) by the user.
	 *
	 * @param string $client the id of the client
	 * @param array $claims the requested claims
	 * @return bool
	 */
	public function hasVisitedClaims( string $client, array $claims ) {
		if ( ! isset( $this->clients[ $client ] ) ) {
			return false;
		}

		foreach ( $claims as $claim ) {
			if ( ( ! in_array( $claim, $this->clients[ $client ][ 'authorized' ] ) ) &&
				( ! in_array( $claim, $this->clients[ $client ][ 'denied' ] ) ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Checks if the client has been authorized by the user.
	 *
	 * @param string $client the id of the client
	 * @return bool
	 */
	public function hasAuthorizedClient( string $client ) {
		return isset( $this->clients[ $client ] );
	}

	/**
	 * Marks the claims from the specified client as authorized.
	 *
	 * @param string $client the id of the client
	 * @param array $authorized authorized claims
	 * @param array $denied denied claims
	 * @return void
	 */
	public function authorize( string $client, array $authorized, array $denied ) {
		$this->clients[ $client ][ 'authorized' ] = $authorized;
		$this->clients[ $client ][ 'denied' ] = $denied;
	}

	/**
	 * Returns the users status.
	 *
	 * Return values:
	 * - true: a user is logged in
	 * - false: anonymous user
	 * - null: user does not exist
	 * @param void
	 * @return bool
	 */
	public function isLoggedIn( ) {
		return $this->status;
	}

	/**
	 * Returns if the user exists.
	 *
	 * @param void
	 * @return bool
	 */
	public function exists( ) {
		return $this->status === null;
	}
}
