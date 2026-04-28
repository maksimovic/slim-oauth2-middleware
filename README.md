# Chadicus\Slim\OAuth2\Middleware

> **Fork Notice:** This is a maintained fork of the abandoned [`chadicus/slim-oauth2-middleware`](https://github.com/chadicus/slim-oauth2-middleware) package. Updated for PHP 8.1+ and PSR-15.

[![License](https://poser.pugx.org/maksimovic/slim-oauth2-middleware/license)](https://packagist.org/packages/maksimovic/slim-oauth2-middleware)

PSR-15 middleware for using [OAuth2 Server](http://bshaffer.github.io/oauth2-server-php-docs/) within any PSR-15 compatible framework, including [Slim 4](http://www.slimframework.com/).

## Requirements

PHP 8.1 or later.

## Installation

```sh
composer require maksimovic/slim-oauth2-middleware
```

## Example usage

```php
use Chadicus\Slim\OAuth2\Middleware\Authorization;
use OAuth2;
use OAuth2\Storage;
use OAuth2\GrantType;

$storage = new Storage\Memory([
    'client_credentials' => [
        'administrator' => ['client_id' => 'administrator', 'client_secret' => 'password', 'scope' => 'superUser'],
    ],
]);

$server = new OAuth2\Server(
    $storage,
    ['access_lifetime' => 3600],
    [new GrantType\ClientCredentials($storage)]
);

$auth = new Authorization($server, $container);

// Slim 4
$app->get('/foos', $handler)->add($auth);
$app->post('/foos', $handler)->add($auth->withRequiredScope(['superUser']));
```

`$container` must be either an `ArrayAccess` or expose a `set($key, $value)` method (e.g. PHP-DI). The decoded access token is stored under the `'token'` key on success and added to the request as the `oauth2-token` attribute.

## Development

```sh
composer install
composer test
composer test:coverage
composer cs-check
```

## License

MIT
