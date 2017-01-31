<?php
/**
 * Copyright 2015 Xenofon Spafaridis
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

namespace Phramework\Authentication\JWT;

use \Phramework\Phramework;
use \Phramework\Validate\Validate;
use \Phramework\Authentication\Manager;

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
 * @author Xenofon Spafaridis <nohponex@gmail.com>
 * @uses \Firebase\JWT\JWT
 * @uses password_verify to verify user's password
 * @since 0.0.0
 * @version 1.0.0
 *
 */
class JWT implements \Phramework\Authentication\IAuthentication
{

    /**
     * Test if current request holds authoratation data
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return boolean
     * @todo check jwt token if is jwt
     */
    public function testProvidedMethod($params, $method, $headers)
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
     * @return object|FALSE Returns false on error or the user object on success
     */
    public function check($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($jwt) = sscanf($headers['Authorization'], 'Bearer %s');

        if (!$jwt) {
            return false;
        }

        $secret     = Phramework::getSetting('jwt', 'secret');
        $algorithm  = Phramework::getSetting('jwt', 'algorithm');

        try {
            $token = \Firebase\JWT\JWT::decode($jwt, $secret, [$algorithm]);

            //Call onAuthenticate callback if set
            if (($callback = Manager::getOnCheckCallback()) !== null) {
                call_user_func(
                    $callback,
                    $token->data
                );
            }

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
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array  $headers  Request headers
     * @return false|array  Returns false on failure
     */
    public function authenticate($params, $method, $headers)
    {
        //Require email and password set in params
        $validationModel = new \Phramework\Validate\ObjectValidator(
            [
                'email'    => new \Phramework\Validate\EmailValidator(3, 100),
                'password' => new \Phramework\Validate\StringValidator(3, 128, null, true),
            ],
            ['email', 'password']
        );

        $parsed = $validationModel->parse($params);

        $email = $parsed->email;
        $password = $parsed->password;

        //Get user object
        $user = call_user_func(Manager::getUserGetByEmailMethod(), $email);

        if (!$user) {
            return false;
        }

        // Verify user's password (password is stored as hash)
        if (!password_verify($password, $user['password'])) {
            return false;
        }

        $secret     = Phramework::getSetting('jwt', 'secret');
        $algorithm  = Phramework::getSetting('jwt', 'algorithm');
        $serverName = Phramework::getSetting('jwt', 'server');

        $tokenId    = base64_encode(\random_bytes(32));
        $issuedAt   = time();
        $notBefore  = $issuedAt //Adding seconds
            + Phramework::getSetting('jwt', 'nbf', 0);
        $expire     = $notBefore //Adding seconds
            + Phramework::getSetting('jwt', 'exp', 3600);

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
        foreach (Manager::getAttributes() as $attribute) {
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
        if (($callback = Manager::getOnAuthenticateCallback()) !== null) {
            call_user_func(
                $callback,
                (object) $data['data'],
                $jwt
            );
        }

        return [(object) $data['data'], $jwt];
    }
}
