<?php
/**
 * Copyright 2015 Spafaridis Xenofon
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Phramework\JWT\Models;

use \Phramework\Validate\Validate;

/**
 * JWT authentication implementation for phramework
 * Defined settings:
 * - jwt[]
 *   - secret
 *   - server Server's name
 *   - algorithm
 *   - [nbf] Not before offset in seconds, default 0
 *   - [exp] Expiration offset in seconds, default 3600
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @author Spafaridis Xenophon <nohponex@gmail.com>
 * @uses \Firebase\JWT\JWT
 * @uses password_verify to verify user's password
 *
 */
class JWT extends \Phramework\Models\Authentication
{
    /**
     * MUST be set
     * @var callable
     */
    protected static $userGetByEmailMethod = null;

    /**
     * @var string[]
     */
    protected static $attributes = [];

    /**
     * @var callable|null
     */
    protected static $onAuthenticateCallback = null;

    /**
     * Set the method that accepts email and returns a user object
     * MUST containg a password, id, this method MUST also contain any other
     * attribute specified in JWT::setAttributes method
     * @param callable $callable
     */
    public static function setUserGetByEmailMethod($callable)
    {
        if (!is_callable($callable)) {
            throw new \Exception('Provided method is not callable');
        }

        self::$userGetByEmailMethod = $callable;
    }

    /**
     * Set attributes to be copied from user record.
     * Both `user_id` and `id` will use the user's id attribute
     * @param string[] $attributes
     */
    public static function setAttributes($attributes)
    {
        self::$attributes = $attributes;
    }

    /**
     * Set a callback that will be executed after a successful authenticate
     * execution, `jwt` token string and `data` array will be provided to the
     * defined callback.
     * @param callable $callable
     */
    public static function setOnAuthenticateCallback($callable)
    {
        if (!is_callable($callable)) {
            throw new \Exception('Provided method is not callable');
        }

        self::$onAuthenticateCallback = $callable;
    }

    /**
     * Test if current request holds authoratation data
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return boolean
     */
    public static function setProvidedMethod($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($jwt) = sscanf($headers['Authorization'], 'Bearer %s');

        if (!$jwt) {
            return false;
        }

        return true;
    }

    /**
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return array|FALSE Returns false on error or the user object on success
     */
    public static function check($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($jwt) = sscanf($headers['Authorization'], 'Bearer %s');

        if (!$jwt) {
            return false;
        }

        $secret     = \Phramework\Phramework::getSetting('jwt', 'secret');
        $algorithm  = \Phramework\Phramework::getSetting('jwt', 'algorithm');

        try {
            $token = \Firebase\JWT\JWT::decode($jwt, $secret, [$algorithm]);

            return $token->data;
        } catch (\Exception $e) {
            /*
             * the token was not able to be decoded.
             * this is likely because the signature was not able to be verified (tampered token)
             */
            return false;
        }
    }

    /**
     * Authenticate a user using JWT authentication method
     * @param  string $email    User's email
     * @param  string $password User's password
     * @return false  Returns false on failure
     * @todo read nbf and exp from settings
     */
    public static function authenticate($email, $password)
    {
        if (!self::$userGetByEmailMethod) {
            throw new \Phramework\Exceptions\ServerException(
                'getUserByEmail is not set'
            );
        }

        $email = Validate::email($email);

        $user = call_user_func(self::$userGetByEmailMethod, $email);

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password'])) {
            return false;
        }

        $secret     = \Phramework\Phramework::getSetting('jwt', 'secret');
        $algorithm  = \Phramework\Phramework::getSetting('jwt', 'algorithm');
        $serverName = \Phramework\Phramework::getSetting('jwt', 'server');

        $tokenId    = base64_encode(\mcrypt_create_iv(32));
        $issuedAt   = time();
        //Adding seconds
        $notBefore  = $issuedAt
            + \Phramework\Phramework::getSetting('jwt', 'nbf', 0);
        //Adding seconds
        $expire     = $notBefore
            + \Phramework\Phramework::getSetting('jwt', 'exp', 3600);

        /*
         * Create the token as an array
        */
        $data = [
            'iat'  => $issuedAt,  // Issued at: time when the token was generated
            'jti'  => $tokenId,   // Json Token Id: an unique identifier for the token
            'iss'  => $serverName,// Issuer
            'nbf'  => $notBefore, // Not before
            'exp'  => $expire,    // Expire
            'data' => [           // Data related to the signer user
                'id' => $user['id']
            ]
        ];

        //copy user attributes to jwt's data
        foreach (self::$attributes as $attribute) {
            if (!isset($user[$attribute])) {
                throw new \Phramework\Exceptions\ServerException(sprintf(
                    'Attribute "%s" is not set in user object',
                    $attribute
                ));
            }
            $data['data'][$attribute] = $user[$attribute];
        }

        $jwt = \Firebase\JWT\JWT::encode(
            $data, //Data to be encoded in the JWT
            $secret, // The signing key
            $algorithm //Algorithm used to sign the token
        );

        //Call onAuthenticate callback if set
        if (self::$onAuthenticateCallback) {
            call_user_func(
                $onAuthenticateCallback,
                $jwt,
                $data
            );
        }

        return $jwt;
    }
}
