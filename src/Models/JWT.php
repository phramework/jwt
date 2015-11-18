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
    /**
     * Set the method that accepts email and returns a user object
     * containg a password
     * @param [type] $callable [description]
     */
    public function setGetUserByEmail($callable)
    {

    }

    /**
     * @param  array  $params  Request parameters
     * @param  string $method  Request method
     * @param  array $headers  Request headers
     * @return array|FALSE Returns false on error or the user object on success
     */
    public static function check($params, $method, $headers)
    {
        //read from token
        return false;
    }

    public static function authenticate($email, $password)
    {
        //check if authenticated
    }
}
