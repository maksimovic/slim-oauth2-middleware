<?php

namespace ChadicusTest\Slim\OAuth2\Middleware;

use ArrayObject;
use Chadicus\Slim\OAuth2\Middleware\Authorization;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use OAuth2;
use OAuth2\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 */
#[CoversClass(Authorization::class)]
final class AuthorizationTest extends TestCase
{
    /**
     * Verify basic behavior of __invoke()
     */
    #[Test]
    public function invoke(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $next = function ($request, $response) use ($expectedToken) {
            $this->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return $response;
        };

        $middleware($request, new Response(), $next);

        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify behavior of __invoke() with expired access token.
     */
    #[Test]
    public function invokeExpiredToken(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => strtotime('-1 minute'),
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $middleware = new Authorization($server, new ArrayObject());

        $next = function () {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            '{"error":"invalid_token","error_description":"The access token provided has expired"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify basic behaviour of withRequiredScope().
     */
    #[Test]
    public function withRequiredScope(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'allowFoo anotherScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => 'allowFoo anotherScope',
        ];
        $next = function ($request, $response) use ($expectedToken) {
            $this->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return $response;
        };

        $response = $middleware->withRequiredScope(['allowFoo'])->__invoke($request, new Response(), $next);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify behaviour of withRequiredScope() with insufficient scope.
     */
    #[Test]
    public function withRequiredScopeInsufficientScope(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'aScope anotherScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $middleware = new Authorization($server, new ArrayObject(), ['allowFoo']);

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided '
            . 'by the access token"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify behavior of __invoke() without access token.
     */
    #[Test]
    public function invokeNoTokenProvided(): void
    {
        $storage = new Storage\Memory([]);

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', []);

        $middleware = new Authorization($server, new ArrayObject());

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * Verify __invoke() with scopes using OR logic.
     */
    #[Test]
    public function invokeWithEitherScope(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'basicUser withPermission anExtraScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container, ['superUser', ['basicUser', 'withPermission']]);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => 'basicUser withPermission anExtraScope',
        ];
        $next = function ($request, $response) use ($expectedToken) {
            $this->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return $response;
        };

        $response = $middleware($request, new Response(), $next);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify behavior of the middleware with empty scope.
     */
    #[Test]
    public function invokeWithEmptyScope(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container, []);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $next = function ($request, $response) use ($expectedToken) {
            $this->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return $response;
        };

        $middleware($request, new Response(), $next);

        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify Content-Type header is added to response.
     */
    #[Test]
    public function invokeAddsContentType(): void
    {
        $storage = new Storage\Memory([]);

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', []);

        $middleware = new Authorization($server, new ArrayObject());

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Verify Content-Type header remains unchanged if OAuth2 response contains the header.
     */
    #[Test]
    public function invokeRetainsContentType(): void
    {
        $oauth2ServerMock = $this->getMockBuilder(OAuth2\Server::class)
            ->disableOriginalConstructor()
            ->getMock();
        $oauth2ServerMock->method('verifyResourceRequest')->willReturn(false);
        $oauth2ServerMock->method('getResponse')->willReturn(
            new OAuth2\Response([], 400, ['Content-Type' => 'text/html'])
        );

        $middleware = new Authorization($oauth2ServerMock, new ArrayObject());
        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware(new ServerRequest(), new Response(), $next);
        $this->assertSame('text/html', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Ensure $container must be an instance of ArrayAccess or have a set() method.
     */
    #[Test]
    public function constructWithInvalidContainer(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("\$container does not implement ArrayAccess or contain a 'set' method");
        $oauth2ServerMock = $this->getMockBuilder(OAuth2\Server::class)
            ->disableOriginalConstructor()
            ->getMock();
        new Authorization($oauth2ServerMock, new \StdClass());
    }

    /**
     * Verify middleware cannot be constructed with a pure PSR-11 container (no set method).
     */
    #[Test]
    public function constructWithPSR11Container(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("\$container does not implement ArrayAccess or contain a 'set' method");
        $container = $this->getMockBuilder(ContainerInterface::class)->getMock();
        $oauth2ServerMock = $this->getMockBuilder(OAuth2\Server::class)
            ->disableOriginalConstructor()
            ->getMock();
        new Authorization($oauth2ServerMock, $container);
    }

    /**
     * Verify middleware can use interop container with set() method.
     */
    #[Test]
    public function invokeWithInteropContainer(): void
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = (new \DI\ContainerBuilder())->build();

        $middleware = new Authorization($server, $container);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $next = function ($request, $response) use ($expectedToken) {
            $this->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return $response;
        };

        $middleware($request, new Response(), $next);

        $this->assertSame($expectedToken, $container->get('token'));
    }

    /**
     * Verify withRequiredScope returns a new instance (clone) with different scopes.
     */
    #[Test]
    public function withRequiredScopeReturnsClone(): void
    {
        $oauth2ServerMock = $this->getMockBuilder(OAuth2\Server::class)
            ->disableOriginalConstructor()
            ->getMock();

        $middleware = new Authorization($oauth2ServerMock, new ArrayObject());
        $scoped = $middleware->withRequiredScope(['someScope']);

        $this->assertInstanceOf(Authorization::class, $scoped);
        $this->assertNotSame($middleware, $scoped);
    }

    /**
     * Verify TOKEN_ATTRIBUTE_KEY constant value.
     */
    #[Test]
    public function tokenAttributeKeyConstant(): void
    {
        $this->assertSame('oauth2-token', Authorization::TOKEN_ATTRIBUTE_KEY);
    }
}
