<?php

namespace Hunter\jwt_auth;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response\JsonResponse;
use Hunter\jwt_auth\Policier;

/**
 * Provides admin module permission auth.
 */
class JwtAuthPermission {

  /**
   * Returns bool value of jwt auth permission.
   *
   * @return bool
   */
  public function handle(ServerRequestInterface $request, ResponseInterface $response, callable $next) {
      $bearer = $this->getTokenHeader($request);
      if (is_null($bearer) || !preg_match('/^Bearer\s+(.+)/', trim($bearer), $match)) {
          return new JsonResponse(
              $this->getUnauthorizedMessage()
          );
      }
      $token = trim(end($match));
      $policier = policier();
      if (!$policier->verify($token)) {
          return new JsonResponse(
              $this->getUnauthorizedMessage()
          );
      }
      if ($policier->isExpired($token)) {
          return new JsonResponse(
              $this->getUnauthorizedMessage()
          );
      }
      $policier->plug($token);
      return $next($request, $response);
  }

  /**
   * @inheritdoc
   */
  protected function getTokenHeader($request) {
      $header = $request->getHeader('token');
      return !empty($header) ? $header[0] : '';
  }

  /**
   * Get Error message
   *
   * @return array
   */
  public function getUnauthorizedMessage() {
      return [
          'message' => 'unauthorized',
          'error' => true
      ];
  }

  /**
   * Get Error message
   *
   * @return array
   */
  public function getExpirationMessage() {
      return [
          'message' => 'token is expired',
          'expired' => true,
          'error' => true
      ];
  }

  /**
   * Get Expirate response code
   *
   * @return int
   */
  public function getExpirationStatusCode() {
      return 403;
  }

  /**
   * Get Unauthorized response code
   *
   * @return int
   */
  public function getUnauthorizedStatusCode() {
      return 403;
  }

}
