<?php

namespace Phramework\JWT\Models;

use \Phramework\Phramework;

class JWTTest extends \PHPUnit_Framework_TestCase
{
    protected static $users = [];

    public static function getByEmailWithPassword($email)
    {
        //Search in defiened users by email
        $users = array_filter(
            self::$users,
            function ($user) use ($email) {
                return ($user['email'] == $email);
            }
        );

        if (count($users) == 0) {
            return false;
        }

        return $users[0];
    }

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
        //NOTE, in order testAuthenticateSuccess to work all users must
        //have this password
        self::$users = [
            [
                'id' => 1,
                'email' => 'nohponex@gmail.com',
                'password' => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'user'
            ],
            [
                'id' => 2,
                'email' => 'xenofon@auth.gr',
                'password' => password_hash('123456', PASSWORD_BCRYPT),
                'user_type' => 'moderator'
            ],
        ];

        $settings = [
            'jwt' => [
                'secret' => 'aabsLgq31/K+zXcyAqpdaabszyaabsoatAmnuwaH0Pgx4lzqjHtBmQ==',
                'algorithm' => 'HS256',
                'server' => 'test'
            ]
        ];

        //Initliaze Phramework, to set settings
        $phramework = new Phramework(
            $settings,
            (new \Phramework\URIStrategy\URITemplate([]))
        );

        //Set authentication class
        Phramework::setAuthenticationClass(
            JWT::class
        );

        //Set method to fetch user object, including password attribute
        JWT::setUserGetByEmailMethod(
            [JWTTest::class, 'getByEmailWithPassword']
        );

        JWT::setAttributes(
            ['user_type', 'email']
        );
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown()
    {

    }

    /**
     * @covers Phramework\JWT\Models\JWT::check
     */
    public function testCheckFailure()
    {

        $this->assertFalse(JWT::check(
            [],
            Phramework::METHOD_GET,
            []
        ), 'Expect false, since Authorization header is not provided');

        $this->assertFalse(JWT::check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Basic ABCDEF']
        ), 'Expect false, since Authorization header is not Bearer');

        $this->assertFalse(JWT::check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer xsadsadas']
        ), 'Expect false, since token makes no sense');

        $this->assertFalse(JWT::check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ']
        ), 'Expect false, since token is not correct');
    }

    /**
     * @covers Phramework\JWT\Models\JWT::authenticate
     * @expectedException Exception
     */
    public function testAuthenticateExpectException()
    {
        JWT::authenticate('wrongEmailType', '123456');
    }

    /**
     * @covers Phramework\JWT\Models\JWT::authenticate
     */
    public function testAuthenticateFailure()
    {
        $this->assertFalse(
            JWT::authenticate('not@found.com', '123456'),
            'Expect false, sinse user email doesn`t exist'
        );

        $this->assertFalse(
            JWT::authenticate(self::$users[0]['email'], 'wrong'),
            'Expect false, sinse user password is wrong'
        );
    }

    /**
     * @covers Phramework\JWT\Models\JWT::authenticate
     */
    public function testAuthenticateSuccess()
    {
        //Pick a random user index
        $index = 0; //rand(0, count(self::$users) - 1);

        $token = JWT::authenticate(
            self::$users[$index]['email'],
            '123456' //Since password is the same for all of them
        );

        $this->assertInternalType('string', $token);

        return [$index, $token];
    }

    /**
     * @covers Phramework\JWT\Models\JWT::check
     * @depends testAuthenticateSuccess
     */
    public function testCheckSuccess($indexToken)
    {
        list($index, $token) = $indexToken;

        $user = JWT::check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer ' . $token]
        );

        $this->assertInternalType('object', $user, 'Expect an object');

        $this->assertObjectHasAttribute('id', $user);
        $this->assertObjectHasAttribute('email', $user);
        $this->assertObjectHasAttribute('user_type', $user);
        $this->assertObjectNotHasAttribute('password', $user);

        $this->assertSame(self::$users[$index]['id'], $user->id);
        $this->assertSame(self::$users[$index]['email'], $user->email);
        $this->assertSame(self::$users[$index]['user_type'], $user->user_type);
    }
}
