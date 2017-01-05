<?php
require_once __DIR__ . '/../vendor/autoload.php';

ini_set( 'display_errors', 1 );
error_reporting( E_ALL );


use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class YAOCOApplication extends Application {
	use Application\UrlGeneratorTrait;
}

$app = new YAOCOApplication( );
$app[ 'debug' ] = true;

$app->register( new Silex\Provider\TwigServiceProvider( ), array(
	'twig.path' => __DIR__ . '/../views',
));
$app->register( new Silex\Provider\ServiceControllerServiceProvider( ) );
$app->register( new Silex\Provider\SecurityServiceProvider( ) );
$app->register( new Silex\Provider\SessionServiceProvider( ) );
$app->register( new Silex\Provider\DoctrineServiceProvider( ), array(
	'db.options' => array (
		'driver'    => 'pdo_mysql',
		'host'      => 'localhost',
		'dbname'    => 'oicp',
		'user'      => 'oicp',
		'password'  => 'oicp',
		'charset'   => 'utf8mb4',
	),
) );

$dbConf = array(
	'dsn' => 'mysql:dbname=oicp;host=localhost',
	'username' => 'oicp',
 	'password' => 'oicp',
);

// define yaoco as ServiceProvider
$app[ 'yaoco' ] = function( ) {
	return new YAOCO\Server( );
};

// initiate the OpenID Connect server
$app->before( function( Request $request, Application $app ) use ( $dbConf ) {
	$app[ 'yaoco' ]->initiate( $app, $dbConf );
} );

$app[ 'yaocouserprovider' ] = function( ) use ( $app ) {
	return new YAOCO\UserManager( $app[ 'db' ], $app[ 'security.default_encoder' ] );
};

# PW: foo
# login_path has to be outside the secured area
# login_check has to be inside the secured area
# logout_path has to be inside the secured area
# link to logout: <a href="{{ path('server_logout') }}">Logout</a>
# all "/" are replaced by "_"
$app[ 'security.firewalls' ] = array(
	'secured' => array(
		'form' => array( 'login_path' => '/login', 'check_path' => '/server/login_check' ),
		'logout' => array( 'logout_path' => '/server/logout', 'invalidate_session' => true ),
		'users' => $app[ 'yaocouserprovider' ],
		'anonymous' => true,
	),
);

$app[ 'security.access_rules' ] = array(
	//array( '^/server/', 'ROLE_USER', 'https' ),
	array( '^/server/', 'ROLE_USER' ),
);


$app->get( '/login', function( Request $request ) use ( $app ) {
	return $app[ 'twig' ]->render( 'login.twig.html', array(
		'error' => $app[ 'security.last_error' ]( $request ),
		'last_username' => $app[ 'session' ]->get( '_security.last_username' ),
	));
} )->bind( 'login' );

// add the routes defined by the OpenID Connect server to Silex's routing
foreach( $app[ 'yaoco' ]->getRoutes( ) as $name => $route ) {
	// add the routes defined by the server
	if ( $route[ 'method' ] === 'get' ) {
		$app->get( $route[ 'route' ], 'yaoco:' . $route[ 'function' ] )->bind( $name );
	} else {
		$app->post( $route[ 'route' ], 'yaoco:' . $route[ 'function' ] )->bind( $name );
	}
}

// create an http foundation request implementing OAuth2\RequestInterface
$request = OAuth2\HttpFoundationBridge\Request::createFromGlobals( );

$app->run( $request );
