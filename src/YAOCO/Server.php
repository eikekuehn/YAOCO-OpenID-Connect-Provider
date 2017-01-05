<?php
namespace YAOCO;

use OAuth2\Server as OAuth2Server;
use OAuth2\Scope;
use OAuth2\Storage\Memory;
use OAuth2\Storage\Pdo;
use OAuth2\OpenID\GrantType\AuthorizationCode;
use OAuth2\GrantType\UserCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\HttpFoundationBridge\Response;
use OAuth2\HttpFoundationBridge\Request;
//use Silex\Application;
//use Symfony\Component\HttpFoundation\Request;
//use Symfony\Component\HttpFoundation\Response;

/**
 * A basic OpenID Connect Server.
 *
 * This server does not necessarily support other OAuth2 endpoints / functionality.
 */
class Server {
	/**
	 * Claims supported by this server.
	 *
	 * As defined in http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	 *
	 * name (string): End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	 * given_name (string): Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
	 * family_name (string): Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
	 * middle_name (string): Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	 * preferred_username (string): Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	 * nickname (string): Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
	 * profile (string): URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
	 * picture (string): URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
	 * website (string): URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
	 * email (string): End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	 * email_verified (boolean): True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
	 * gender (string): End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
	 * birthdate (string): End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just year can result in varying month and day, so the implementers need to take this factor into account to correctly process the dates.
	 * zoneinfo (string): String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
	 * locale (string): End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
	 * phone_number (string): End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
	 * phone_number_verified (boolean):	True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
	 * address (JSON object): End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 5.1.1.
	 * update_at (string): Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	 * @var array
	 */
	private $supportedClaims = array(
		'user_id' => array( 'type' => 'username', 'required' => true, 'label' => 'Username', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'name' => array( 'type' => 'text', 'required' => false, 'label' => 'Full Name', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'given_name' => array( 'type' => 'text', 'required' => false, 'label' => 'Given Name', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'family_name' => array( 'type' => 'text', 'required' => false, 'label' => 'Family	Name', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'middle_name' => array( 'type' => 'text', 'required' => false, 'label' => 'Middle Name', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'preferred_username' => array( 'type' => 'username', 'required' => false, 'label' => 'Preferred Username', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'nickname' => array( 'type' => 'text', 'required' => false, 'label' => 'Nickname', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'profile' => array( 'type' => 'url', 'required' => false, 'label' => 'Profile URL', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'picture' => array( 'type' => 'url', 'required' => false, 'label' => 'Profile Picture URL', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'website' => array( 'type' => 'url', 'required' => false, 'label' => 'Website URL', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'email' => array( 'type' => 'email', 'required' => false, 'label' => 'Email', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'email_verified' => array( 'type' => 'bool', 'required' => false, 'label' => 'Email Verified', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => true ),
		'gender' => array( 'type' => 'text', 'required' => false, 'label' => 'Gender', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'birthdate' => array( 'type' => 'date', 'required' => false, 'label' => 'Birthdate', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'zoneinfo' => array( 'type' => 'text', 'required' => false, 'label' => 'Time Zone', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'locale' => array( 'type' => 'text', 'required' => false, 'label' => 'Interface Language', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'phone_number' => array( 'type' => 'tel', 'required' => false, 'label' => 'Phone Number', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'phone_number_verified' => array( 'type' => 'bool', 'required' => false, 'label' => 'Phone Number Verified', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => true ),
		'address' => array( 'type' => 'address', 'required' => false, 'label' => 'Address', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => false ),
		'updated_at' => array( 'type' => 'time', 'required' => false, 'label' => 'Last Update', 'note' => 'Only [a-zA-Z0-9]...', 'readonly' => true ),
	);

	/**
	 * Scopes supported by this server and the claims they contain.
	 *
	 * @var array
	 */
	private $supportedScopes = array(
		'openid' => array( ),
		'offline_access' => array( ),
		'profile' => array( 'user_id', 'name', 'given_name', 'family_name', 'middle_name', 'preferred_username', 'nickname', 'profile', 'picture', 'website', 'gender', 'birthdate', 'locale', 'zoneinfo', 'updated_at' ),
		'email' => array( 'email', 'email_verified' ),
		'phone' => array( 'phone_number', 'phone_number_verified' ),
		'address' => array( 'address' ),	
	);

	/**
	 * Those routes have to be configured for the server to work.
	 *
	 * @var array
	 */
	private $routes = array(
		'index' => array( 'route' => '/', 'function' => 'controllerIndex', 'method' => 'get', 'display' => true ),
		'yaoco.routes.authorize' => array( 'route' => '/server/authorize', 'function' => 'controllerAuthorize', 'method' => 'get', 'display' => true ),
		'yaoco.routes.authorizeclaims' => array( 'route' => '/server/authorize', 'function' => 'controllerAuthorizeClaims', 'method' => 'post', 'display' => true ),
		'yaoco.routes.token.get' => array( 'route' => '/token', 'function' => 'controllerToken', 'method' => 'get', 'display' => true ),
		'yaoco.routes.token.post' => array( 'route' => '/token', 'function' => 'controllerToken', 'method' => 'post', 'display' => true ),
		'yaoco.routes.resource.get' => array( 'route' => '/resource', 'function' => 'controllerResource', 'method' => 'get', 'display' => true ),
		'yaoco.routes.resource.post' => array( 'route' => '/resource', 'function' => 'controllerResource', 'method' => 'post', 'display' => true ),
		'yaoco.routes.jwks' => array( 'route' => '/jwks', 'function' => 'controllerJWKS', 'method' => 'get', 'display' => true ),
		'yaoco.routes.wellknown' => array( 'route' => '/.well-known/openid-configuration', 'function' => 'controllerWellKnown', 'method' => 'get', 'display' => true ),
		'yaoco.routes.aboutme' => array( 'route' => '/server/aboutme', 'function' => 'controllerAboutMe', 'method' => 'get', 'display' => true ),
		'yaoco.routes.createme' => array( 'route' => '/server/createme', 'function' => 'controllerCreateMe', 'method' => 'get', 'display' => true ),
		'yaoco.routes.saveme' => array( 'route' => '/server/saveme', 'function' => 'controllerSaveMe', 'method' => 'post', 'display' => true ),
		// @todo
		'yaoco.routes.sessioncheck' => array( 'route' => '/sessioncheck', 'function' => 'controllerSessionCheck', 'method' => 'get', 'display' => true ),
		'yaoco.routes.sessionend' => array( 'route' => '/sessionend', 'function' => 'controllerIndex', 'method' => 'get', 'display' => true ),
		'yaoco.routes.registration' => array( 'route' => '/registration', 'function' => 'controllerIndex', 'method' => 'get', 'display' => true ),
		'yaoco.routes.docs' => array( 'route' => '/docs', 'function' => 'controllerIndex', 'method' => 'get', 'display' => true ),
	);

	/**
	 * The base url.
	 *
	 * @var string
	 */
	private $urlBase = '';

	/**
	 * Holds the OAuth2 Server.
	 *
	 * @var OAuth2\Server
	 */
	private $server;

	/**
	 * Holds the Request.
	 *
	 * @var OAuth2\HttpFoundationBridge\Request
	 */
	private $request;

	/**
	 * Holds the Response.
	 *
	 * @var OAuth2\HttpFoundationBridge\Response
	 */
	private $response;

	/**
	 * Holds the template engine.
	 *
	 * @var Twig_Environment
	 */
	private $templateEngine;

	/**
	 * Holds an object to controll the flow of the application.
	 *
	 * @var Silex\Application
	 */
	private $flow;

	/**
	 * The current user.
	 *
	 * @var YAOCO\User
	 */
	private $currentUser;

	/**
	 * The name of the current user.
	 *
	 * @var string
	 */
	private $currentUserName;

	/**
	 * Object to build and validate forms.
	 *
	 * @var YAOCO\FormHelper
	 */
	private $formHelper;

	/**
	 * Userprovider.
	 *
	 * @var YAOCO\UserManager
	 */
	private $userprovider;

	/**
	 * Constructor.
	 *
	 * Starts the OpenID Connect server.
	 *
	 * It's not possible to use a regular constructor with Silex because TWIG
	 * needs to be loaded after this object has been created.
	 * @param Silex\Application $app the Silex Application object
	 * @param array $dbConf database configuration
	 * @return void
	 */
	public function initiate( \Silex\Application $app, array $dbConf ) {
		// use YAOCO\UserManager
		$this->userprovider = new UserManager( $app[ 'db' ], $app[ 'security.default_encoder' ] );
		$this->templateEngine = $app[ 'twig' ];
		// get the current user's name
		$token = $app[ 'security.token_storage' ]->getToken( );
		$this->flow = $app;
		$this->currentUserName = ( $token !== null ) ? $token->getUserName( ) : 'anon.';
		$this->urlBase = 'http' . ( isset( $_SERVER[ 'HTTPS' ] ) ? 's' : '' ) . '://' . "{$_SERVER[ 'HTTP_HOST' ]}";

		$this->formHelper = new FormHelper( );
		// create an http foundation request implementing OAuth2\RequestInterface
		$this->request = Request::createFromGlobals( );

		$this->startServer( $dbConf );
	}

	/**
	 * Start the server as a basis for all endpoints.
	 *
	 * @param array $dbConf database configuration
	 * @return void
	 */
	private function startServer( array $dbConf ) {

		$db = new Pdo( $dbConf );

		// create array of supported grant types
		$grantTypes = array(
			'authorization_code' => new AuthorizationCode( $db ),
			// YAOCO\UserProvider implements OAuth2\Storage\UserCredentialsInterface
			'user_credentials' => new UserCredentials( $this->userprovider ),
			'refresh_token' => new RefreshToken(
				$db,
				array(
					'always_issue_new_refresh_token' => true,
				)
			),
		);

		// instantiate the oauth server
		$server = new OAuth2Server(
			$db,
			array(
				'enforce_state' => true,
				'allow_implicit' => true,
				'use_openid_connect' => true,
				'issuer' => $this->getIssuer( ),
			),
			$grantTypes
		);

		// create storage
		$keyStorage = new Memory(
			array(
				'keys' => array(
					'public_key'  => file_get_contents( $this->getBaseDir( ) . '/keys/pubkey2.pem' ),
					'private_key' => file_get_contents( $this->getBaseDir( ) . '/keys/privkey2.pem' ),
				)
			)
		);

		$server->addStorage( $keyStorage, 'public_key' );

		$supportedScopes = $this->getSupportedScopes( );
		$defaultScope = array_shift( $supportedScopes );

		$memory = new Memory(
			array(
				'default_scope' => $defaultScope,
				'supported_scopes' => $supportedScopes
			)
		);
		$scopeUtil = new Scope( $memory );
		$server->setScopeUtil( $scopeUtil );

		// add the server to the silex "container" so we can use it in our controllers (see src/OAuth2Demo/Server/Controllers/.*)
		$this->server = $server;

		/**
		 * add HttpFoundataionBridge Response to the container, which returns a silex-compatible response object
		 * @see (https://github.com/bshaffer/oauth2-server-httpfoundation-bridge)
		 */
		$this->response = new Response( );
	}

	/**
	 * Returns the route of a component.
	 *
	 * @param string $name the name of the route
	 * @return string
	 */
	public function getRoute( string $name, bool $url = true ) {
		if ( isset( $this->routes[ $name ]) ) {
			if ( $url ) {
				return $this->urlBase . $this->routes[ $name ][ 'route' ];
			} else {
				return $this->routes[ $name ][ 'route' ];
			}
		} else {
			// @todo raise hell
			return '';
		}
	}

	/**
	 * Returns all configured routes.
	 *
	 * @param void
	 * @return array
	 */
	public function getRoutes( ) {
		return $this->routes;
	}

	/**
	 * Returns an array of scopes that are supported by this server.
	 *
	 * @see YAOCO\Server::$supportedScopes
	 * @param void
	 * @return array
	 */
	public function getSupportedScopes( ) {
		return array_keys( $this->supportedScopes );
	}

	/**
	 * Returns an array of claims supported by this server.
	 *
	 * @see YAOCO\Server::$supportedClaims
	 * @param void
	 * @return array
	 */
	public function getSupportedClaims( ) {
		return array_keys( $this->supportedClaims );
	}

	/**
	 * Returns an array containing all claims the scopes comprise.
	 *
	 * @param array $scopes
	 * @return array
	 */
	public function getClaimsInScopes( array $scopes ) {
		$claims = array( );
		foreach ( $scopes as $scope ) {
			if ( isset( $this->supportedScopes[ $scope ] ) ) {
				$claims = array_merge( $claims, $this->supportedScopes[ $scope ] );
			}
		}
		return $claims;
	}

	/**
	 * Returns an multidimensional array of claims.
	 *
	 * array(
	 *   'scope1' => array(
	 *     'claim1' => CLAIM
	 *   )
	 * )
	 *
	 * @param array $claims an array of claims
	 * @return array
	 */
	public function sortClaimsByScopes( array $claims ) {
		$ordered = array( );

		foreach ( $this->supportedScopes as $scope => $containedClaims ) {
			foreach ( $containedClaims as $claim ) {
				if ( isset( $claims[ $claim ] ) ) {
					$ordered[ $scope ][ $claim ] = $claims[ $claim ];
				}
			}
		}
		return $ordered;
	}

	/**
	 * Returns the path to the root directory of the project.
	 *
	 * root
	 * |- views
	 * |- src
	 * |- vendor
	 * |- keys
	 * |- web
	 * |  |- index.php
	 * @param void
	 * @return string
	 */
	private function getBaseDir( ) {
		return dirname( dirname( dirname( __FILE__  ) ) );
	}

	/**
	 * Return the URL that is used as issuer in the response.
	 *
	 * @param void
	 * @return string
	 */
	private function getIssuer( ) {
		return $this->getRoute( 'index' );
	}

	/**
	 * Function to render a template and return the output.
	 *
	 * Used to separate server functionality from the framework.
	 *
	 * @uses YAOCO\Server::$templateEngine to render the template
	 * @param string $template the name of the template (file or path below /views/ )
	 * @param array $variables variables for the template to render
	 * @return string the rendered template
	 */
	private function renderTemplate( string $template, array $variables ) {
		// depends on Silex + TWIG
		return $this->templateEngine->render( $template, $variables );
	}

	/**
	 * Return a user object of an arbitrary user.
	 *
	 * If no $username is given the current user will be returned.
	 *
	 * If the requested user does not exist a user with username "anon." will be
	 * returned.
	 *
	 * You may check with: $user->exists( ) .
	 * In most cases $user->isLoggedIn( ) will suffice.
	 *
	 * If no user is logged in the "anon." user will be returned as well
	 * Check with: $user->isLoggedIn( ) .
	 * Will only return true if the user exists and is logged in.
	 *
	 * @uses YAOCO\Server::$userprovider
	 * @uses YAOCO\Server::$currentUser
	 * @uses YAOCO\Server::$currentUserName
	 * @param string $username the name of the user to load.
	 * @return YAOCO\User
	 */
	private function getUser( $username = '' ) {
		if ( $username !== '' ) {
			// load the specified user
			return $this->userprovider->loadUserByUsername( $username );
		}

		// the current user is requested

		if ( $this->currentUser === null ) {
			// load the current user
			$this->currentUser = $this->userprovider->loadUserByUsername( $this->currentUserName );
		}

		return $this->currentUser;
	}

	/**
	 * Index Controller.
	 *
	 * @param void
	 * @return string response
	 */
	public function controllerIndex( ) {
		return $this->renderTemplate(
			'index.twig.html',
			array(
				'routes' => $this->getRoutes( )
			)
		);
	}

	/**
	 * Displays information about the current user.
	 *
	 * @param void
	 * @return string response
	 */
	public function controllerAboutMe( ) {
		$user = $this->getUser( );

		// create an array to display the user's clients, scopes and claims
		// client
		//  - scopes
		//    - claims
		$clients = array( );

		foreach ( $user->getClients( ) as $client ) {
			$clients[ $client ] = $this->sortClaimsByScopes( $user->getClaimsForClient( $client ) );
		}

		$claims = $user->getClaims( $this->getSupportedClaims( ) );

		$formFields = $this->supportedClaims;

		foreach ( $formFields as $id => $field ) {
			$formFields[ $id ][ 'value' ] = isset( $claims[ $id ] ) ? $claims[ $id ] : '';
		}

		$formFields[ 'password' ] = array(
			'type' => 'password',
			'label' => 'New Password',
			'required' => false
		);

		$formFields[ 'password2' ] = array(
			'type' => 'password',
			'label' => 'New Password (confirm)',
			'required' => false
		);

		$formFields[ 'password_old' ] = array(
			'type' => 'password',
			'label' => 'Current Password',
			'required' => true
		);

		return $this->renderTemplate(
			'aboutme.twig.html',
			array(
				'form' => $this->formHelper->buildForm( 'me', 'yaoco.routes.aboutme', 'yaoco.routes.saveme', $formFields ),
				'name' => $user->getClaim( 'name' ),
				'clients' => $clients,
			)
		);
	}

	/**
	 * Displays a form to create a new user.
	 *
	 * @param void
	 * @return string response
	 */
	public function controllerCreateMe( ) {
		$formFields = $this->supportedClaims;

		$formFields[ 'password' ] = array(
			'type' => 'password',
			'label' => 'New Password',
			'required' => false
		);

		$formFields[ 'password2' ] = array(
			'type' => 'password',
			'label' => 'New Password (confirm)',
			'required' => false
		);

		return $this->renderTemplate(
			'createme.twig.html',
			array(
				'form' => $this->formHelper->buildForm( 'me', 'yaoco.routes.createme', 'yaoco.routes.saveme', $formFields )
			)
		);
	}

	/**
	 * Checks the user input and saves the user data to the database.
	 *
	 * Redirects the user to the original controller in case of an error
	 * or to AboutMe in case of success.
	 *
	 * @param void
	 * @return void
	 */
	public function controllerSaveMe( ) {
		// which controller generated the form?
		$ok = $this->formHelper->checkForm( 'me', $this->request );
		$form = $this->formHelper->getFormData( 'me' );

		if ( ! $ok ) {
			// redirect
			return $this->flow->redirect( $this->getRoute( $form[ 'origin' ] ) );
		}

		$values = array( );
		foreach( $form[ 'fields' ] as $id => $field ) {
			$values[ $id ] = $field[ 'value' ];
		}
		//var_dump( $values );die( );

		if ( ! empty( $values[ 'password' ] ) ) {
			if ( $values[ 'password' ] !== $values[ 'password2'] ) {
				$this->formHelper->setMessageForField( 'me', 'password', 'Passwords do not match.'	);
				return $this->flow->redirect( $this->getRoute( $form[ 'origin' ] ) );
			} else {
				// encode the password
				$values[ 'password' ] = $this->userprovider->encodePassword( $values[ 'password' ] );
				unset( $values[ 'password2' ] );
			}
		} else {
			unset( $values[ 'password' ] );
			unset( $values[ 'password2' ] );
		}

		if ( $form[ 'origin' ] === 'yaoco.routes.aboutme' ) {
			$user = $this->getUser( $values[ 'user_id' ] );
			$oldData = $user->getDataForSaving( );
			// copy some values the user might not change
			$values[ 'id' ] = $oldData[ 'data' ][ 'id' ];

			if ( ! $this->userprovider->isPasswordValid( $values[ 'password_old'], $oldData[ 'data' ][ 'password' ] ) ) {
				$this->formHelper->setMessageForField( 'me', 'password_old', 'There seems to be a typo here.' );
				return $this->flow->redirect( $this->getRoute( $form[ 'origin' ] ) );
			}

			unset( $values[ 'password_old' ] );

			// load the data into the userobject and save it to the db
			$user->initiate( $values, $oldData[ 'clients'], true );
			$this->userprovider->saveUser( $user );
		} elseif ( $form[ 'origin' ] === 'yaoco.routes.createme' ) {
			$this->userprovider->createUser( $values );
		}

		$this->formHelper->clearFormData( 'me' );
		return $this->flow->redirect( $this->getRoute( 'yaoco.routes.aboutme' ) );
	}

	/**
	 * This endpoint authenticates the user and lets her or him authorize clients.
	 *
	 * To access this endpoint the user has to be logged in.
	 * @param void
	 * @return string response
	 */
	public function controllerAuthorize( ) {
		// validate the authorize request.  if it is invalid, redirect back to the client with the errors in tow
		if ( ! $this->server->validateAuthorizeRequest( $this->request, $this->response ) ) {
			return $this->server->getResponse( );
		}

		// check in the database if the user already authorized the app
		$user = $this->getUser( );
		$client = $this->request->query( 'client_id', $this->request->request( 'client_id' ) );
		$scopes = explode( ' ', $this->request->query( 'scope', $this->request->request( 'scope' ) ) );
		$claims = $this->getClaimsInScopes( $scopes );

		if ( $user->isLoggedIn( ) && $authorized = $user->hasVisitedClaims( $client, $claims ) ) {
			// the user has the visited the requested scopes for this client
			// so we authenticate her or him
			return $this->server->handleAuthorizeRequest( $this->request, $this->response, $authorized, $user->getClaim( 'user_id' ) );
		}

		$claimsDefault = array( );
		foreach ( $claims as $claim ) {
			$claimsDefault[ $claim ] = 'checked';
		}

		// the user has not yet authorized the client or visited all requested scopes
		// so we display the "do you want to authorize?" form
		return $this->renderTemplate(
			'authorize.twig.html',
			array(
				'client_id' => $this->request->get( 'client_id' ),
				'response_type' => $this->request->get( 'response_type' ),
				'requested' => $this->sortClaimsByScopes( $claimsDefault )
			)
		);
	}

	/**
	 * This is called once the user decides to authorize or cancel the client app's
	 * authorization request
	 */
	public function controllerAuthorizeClaims( ) {
		$agreed = (bool) $this->request->get( 'authorize' );

		// get the user
		$user = $this->getUser( );
		$client = $this->request->query( 'client_id', $this->request->request( 'client_id' ) );
		$scopes = explode( ' ', $this->request->query( 'scope', $this->request->request( 'scope' ) ) );
		// check which claims were authorized by the user
		$authorized = $this->request->get( 'claims' );
		// to see which claims were decline we have to get the diff between
		// the requested scopes / claims and the authorized claims
		$denied = array_diff( $this->getClaimsInScopes( $scopes ), $authorized );

		if ( $agreed && $user->isLoggedIn( ) ) {
			$user->authorize( $client, $authorized, $denied );
			$this->userprovider->saveUser( $user );
		}

		return $this->server->handleAuthorizeRequest( $this->request, $this->response, $agreed, $user->getClaim( 'user_id' ) );
	}

	/**
	 * This is called by the client app once the client has obtained an access
	 * token for the current user.  If the token is valid, the resource (in this
	 * case, the "friends" of the current user) will be returned to the client
	 */
	public function controllerResource( ) {
		if ( ! $this->server->verifyResourceRequest( $this->request, $this->response ) ) {
			return $this->server->getResponse( );
		} else {
			$token = $this->server->getAccessTokenData( $this->request );
			$user = $this->getUser( $token[ 'user_id' ] );

			if ( ! $user->exists( ) ) {
				$response = array( );
			}

			$response = $user->getClaimsForClient( $token[ 'client_id' ] );

			// the specification states that emtpy or denied values have
			// to be omitted
			foreach ( $response as $key => $value ) {
				if ( empty( $value ) ) {
					unset( $response[ $key ] );
				}
			}

			return json_encode( $response );
		}
	}

	/**
	 * This is called by the client app once the client has obtained
	 * an authorization code from the Authorize Controller (@see OAuth2Demo\Server\Controllers\Authorize).
	 * If the request is valid, an access token will be returned
	 */
	public function controllerToken( ) {
		return $this->server->handleTokenRequest( $this->request, $this->response );
	}

	/**
	 * JSON Web Key Storage contains the signing key(s) the RP uses to validate
	 * signatures from the OP.
	 *
	 * @param void
	 * @return string response
	 */
	public function controllerJWKS( ) {
		$jwksString = file_get_contents( $this->getBaseDir( ) . '/keys/jwks' );
		$jwksJSON = json_decode( $jwksString, true );
		return json_encode( $jwksJSON );
	}

	/**
	 * Implements Auto Discovery.
	 *
	 * Specification: http://openid.net/specs/openid-connect-discovery-1_0.html
	 *
	 * @param void
	 * @return string response
	 */
	public function controllerWellKnown( ) {
		$wellKnown = array(
			// those have to be set to guarantee service
			"issuer" => $this->getIssuer( ),
			"authorization_endpoint" => $this->getRoute( 'yaoco.routes.authorize' ),
			"token_endpoint" => $this->getRoute( 'yaoco.routes.token.get' ),
			"userinfo_endpoint" => $this->getRoute( 'yaoco.routes.resource.get' ),
			"jwks_uri" => $this->getRoute( 'yaoco.routes.jwks' ),
			"scopes_supported" => $this->getSupportedScopes( ), 
			"claims_supported" => $this->getSupportedClaims( ),
			// methods need to written
			"registration_endpoint" => $this->getRoute( 'yaoco.routes.registration' ),
			"service_documentation" => $this->getRoute( 'yaoco.routes.docs' ),
			"end_session_endpoint" => $this->getRoute( 'yaoco.routes.sessionend' ),
			"check_session_iframe" => $this->getRoute( 'yaoco.routes.sessioncheck' ),
			// locales need to be implemented
			"ui_locales_supported" => array( "de-DE", "en-GB" ),
			// those I don't yet know
			"claims_parameter_supported" => false,
			"subject_types_supported" => array( "public", "pairwise" ),	
			"acr_values_supported" => array( "urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze" ),
			"response_types_supported" => array( "code", "code id_token", "id_token", "token id_token" ),
			"token_endpoint_auth_methods_supported" => array( "client_secret_basic", "private_key_jwt" ),
			"token_endpoint_auth_signing_alg_values_supported" => array( "RS256", "ES256" ),
			"userinfo_signing_alg_values_supported" => array( "RS256", "ES256", "HS256" ),
			"userinfo_encryption_alg_values_supported" => array( "RSA1_5", "A128KW" ),
			"userinfo_encryption_enc_values_supported" => array( "A128CBC-HS256", "A128GCM" ),
			"id_token_signing_alg_values_supported" => array( "RS256", "ES256", "HS256" ),
			"id_token_encryption_alg_values_supported" => array( "RSA1_5", "A128KW" ),
			"id_token_encryption_enc_values_supported" => array( "A128CBC-HS256", "A128GCM" ),
			"request_object_signing_alg_values_supported" => array( "none", "RS256", "ES256"),
			"display_values_supported" => array( "page" ),//, "popup" ),
			"claim_types_supported" => array( "normal", "distributed")
		);
		return json_encode( $wellKnown ) ;
	}

	/**
	 * Serves the content for an iframe for sessionmanagement.
	 *
	 * @param void
	 * @return stirng response
	 */
	public function controllerSessionCheck( ) {
		return $this->renderTemplate(
			'sessioncheck.twig.html',
			array()
		);
	}
}
