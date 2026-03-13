# Chadicus\Slim\OAuth2\Middleware

> **Fork Notice:** This is a maintained fork of the abandoned [`chadicus/slim-oauth2-middleware`](https://github.com/chadicus/slim-oauth2-middleware) package. Updated for PHP 8.1+.

[![License](https://poser.pugx.org/maksimovic/slim-oauth2-middleware/license)](https://packagist.org/packages/maksimovic/slim-oauth2-middleware)

Middleware for using [OAuth2 Server](http://bshaffer.github.io/oauth2-server-php-docs/) within a [Slim Framework](http://www.slimframework.com/) API.

## Requirements

PHP 8.1 or later.

## Installation

```sh
composer require maksimovic/slim-oauth2-middleware
```

## Example Usage

```php
use Chadicus\Slim\OAuth2\Middleware;
use OAuth2;
use OAuth2\Storage;
use OAuth2\GrantType;
use Slim;

// Set up storage for OAuth2 server
$storage = new Storage\Memory(
    [
        'client_credentials' => [
            'administrator' => [
                'client_id' => 'administrator',
                'client_secret' => 'password',
                'scope' => 'superUser',
            ],
            'foo-client' => [
                'client_id' => 'foo-client',
                'client_secret' => 'p4ssw0rd',
                'scope' => 'basicUser canViewFoos',
            ],
        ],
    ]
);

// Create the OAuth2 server
$server = new OAuth2\Server(
    $storage,
    ['access_lifetime' => 3600],
    [new GrantType\ClientCredentials($storage)]
);

// Create the Slim app
$app = new Slim\App();

// Create the authorization middleware
$authMiddleware = new Middleware\Authorization($server, $app->getContainer());

// No scope required
$app->get('foos', function ($request, $response, $args) {
    // return all foos
})->add($authMiddleware);

// Requires superUser scope OR (basicUser AND canViewFoos)
$app->get('foos/id', function ($request, $response, $id) {
    // return foo details
})->add($authMiddleware->withRequiredScope(['superUser', ['basicUser', 'canViewFoos']]));

// Requires superUser scope
$app->post('foos', function ($request, $response, $args) {
    // create a new foo
})->add($authMiddleware->withRequiredScope(['superUser']));

$app->run();
```

## Development

```sh
composer install
composer test
composer test:coverage
composer cs-check
```

## License

MIT
