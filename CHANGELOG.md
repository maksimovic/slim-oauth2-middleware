# Changelog

## 5.0.0 — 2026-04-28

### Breaking

- `Authorization` now implements `Psr\Http\Server\MiddlewareInterface` (PSR-15) with a `process(ServerRequestInterface, RequestHandlerInterface)` method. The previous double-pass `__invoke($request, $response, $next)` entry point has been removed.
- Dropped `maksimovic/psr-middleware` (the legacy double-pass interface) from `require`.
- Dropped `container-interop/container-interop` (abandoned) from `require`. The runtime `$container` argument still accepts either an `ArrayAccess` or any object with a `set()` method, unchanged — the middleware uses a duck-typed shape, not PSR-11.

### Composer

- Add `psr/http-server-middleware ^1.0`.
- Widen `psr/http-message` to `^1.0 || ^2.0`.
- Bump `php-di/php-di` dev dep to `^7.0`.
- `psr/container` is in `require-dev` only (used in tests; not referenced by `src/`).
