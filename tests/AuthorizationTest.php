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
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 */
#[CoversClass(Authorization::class)]
final class AuthorizationTest extends TestCase
{
    /**
     * Build a RequestHandlerInterface that captures the request it received and returns the given response.
     */
    private function capturingHandler(?ResponseInterface $response = null): RequestHandlerInterface
    {
        return new class ($response ?? new Response()) implements RequestHandlerInterface {
            public ?ServerRequestInterface $captured = null;
            public function __construct(private ResponseInterface $response)
            {
            }
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->captured = $request;
                return $this->response;
            }
        };
    }

    /**
     * Build a RequestHandlerInterface that throws if invoked.
     */
    private function neverCalledHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new \Exception('This will not get executed');
            }
        };
    }

    /**
     * Verify basic behavior of process() with a valid token.
     */
    #[Test]
    public function process(): void
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

        $handler = $this->capturingHandler();
        $middleware->process($request, $handler);

        $this->assertSame($expectedToken, $handler->captured->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify behavior of process() with expired access token.
     */
    #[Test]
    public function processExpiredToken(): void
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

        $response = $middleware->process($request, $this->neverCalledHandler());

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

        $handler = $this->capturingHandler();
        $response = $middleware->withRequiredScope(['allowFoo'])->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken, $handler->captured->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
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

        $response = $middleware->process($request, $this->neverCalledHandler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided '
            . 'by the access token"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify behavior of process() without access token.
     */
    #[Test]
    public function processNoTokenProvided(): void
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

        $response = $middleware->process($request, $this->neverCalledHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * Verify process() with scopes using OR logic.
     */
    #[Test]
    public function processWithEitherScope(): void
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

        $handler = $this->capturingHandler();
        $response = $middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken, $handler->captured->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify behavior of the middleware with empty scope.
     */
    #[Test]
    public function processWithEmptyScope(): void
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

        $handler = $this->capturingHandler();
        $middleware->process($request, $handler);

        $this->assertSame($expectedToken, $handler->captured->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
        $this->assertSame($expectedToken, $container['token']);
    }

    /**
     * Verify Content-Type header is added to response when oauth2 server response has none.
     */
    #[Test]
    public function processAddsContentType(): void
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

        $response = $middleware->process($request, $this->neverCalledHandler());

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Verify Content-Type header remains unchanged if OAuth2 response contains the header.
     */
    #[Test]
    public function processRetainsContentType(): void
    {
        $oauth2ServerMock = $this->getMockBuilder(OAuth2\Server::class)
            ->disableOriginalConstructor()
            ->getMock();
        $oauth2ServerMock->method('verifyResourceRequest')->willReturn(false);
        $oauth2ServerMock->method('getResponse')->willReturn(
            new OAuth2\Response([], 400, ['Content-Type' => 'text/html'])
        );

        $middleware = new Authorization($oauth2ServerMock, new ArrayObject());

        $response = $middleware->process(new ServerRequest(), $this->neverCalledHandler());

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
     * Verify middleware can use a PHP-DI container (has a set() method).
     */
    #[Test]
    public function processWithPhpDiContainer(): void
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

        $handler = $this->capturingHandler();
        $middleware->process($request, $handler);

        $this->assertSame($expectedToken, $handler->captured->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
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
