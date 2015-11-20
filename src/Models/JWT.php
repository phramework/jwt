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

class JWT extends \Phramework\Models\Authentication
{
    protected $getUserByEmail = null;

    /**
     * Set the method that accepts email and returns a user object
     * containg a password
     * @param [type] $callable [description]
     */
    public static function setGetUserByEmail($callable)
    {
        if (!is_callable($callable)) {
            throw new \Exception('Provided method is not callable');
        }

        self::$getUserByEmail = $callable;
    }

    /**
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array $headers  Request headers
     * @return array|FALSE Returns false on error or the user object on success
     */
    public static function check($params, $method, $headers)
    {
        if (!isset($headers['Authorization'])) {
            return false;
        }

        list($jwt) = sscanf($headers['Authorization'], 'Authorization: Bearer %s');

        if (!$jwt) {
            return false;
        }

        $secret    = \Phramework\Phramework::getSetting('jwt', 'secret');
        $algorithm = \Phramework\Phramework::getSetting('jwt', 'algorithm');

        try {

            $token = JWT::decode($jwt, $secretKey, [$algorithm]);

            return [];
        } catch (Exception $e) {
            /*
             * the token was not able to be decoded.
             * this is likely because the signature was not able to be verified (tampered token)
             */
//            header('HTTP/1.0 401 Unauthorized');
            return false;
        }

        //read from token
        //return false;
    }

    public static function authenticate($email, $password)
    {
        if (!self::$getUserByEmail) {
            throw new \Exception('getUserByEmail is not set');
        }

        $email = Validate::email($email);

        $user = self::$getUserByEmail($email);

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password'])) {
            return false;
        }

        header('Content-type: application/json');

        $secret     = \Phramework\Phramework::getSetting('jwt', 'secret');
        $algorithm  = \Phramework\Phramework::getSetting('jwt', 'algorithm');

        $serverName = \Phramework\Phramework::getSetting('jwt', 'server');

        $tokenId    = base64_encode(mcrypt_create_iv(32));
        $issuedAt   = time();
        $notBefore  = $issuedAt + 10;  //Adding 10 seconds
        $expire     = $notBefore + 60; // Adding 60 seconds

        /*
        * Create the token as an array
        */
        $data = [
            'iat'  => $issuedAt,         // Issued at: time when the token was generated
            'jti'  => $tokenId,          // Json Token Id: an unique identifier for the token
            'iss'  => $serverName,       // Issuer
            'nbf'  => $notBefore,        // Not before
            'exp'  => $expire,           // Expire
            'data' => [                  // Data related to the signer user
                'user_id'  => $user['id'], // userid from the users table
                'username' => $user['username'], // User name
            ]
        ];

        $jwt = JWT::encode(
            $data,      //Data to be encoded in the JWT
            $secretKey, // The signing key
            $algorithm  // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
        );

        $unencodedArray = ['jwt' => $jwt];


        echo json_encode($unencodedArray);

        die();
    }
}
