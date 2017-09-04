<?php

namespace Phramework\Authentication\JWT;

use \Phramework\Phramework;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
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
     * @var JWT
     */
    private $object;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
        $this->object = new JWT();

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
        \Phramework\Authentication\Manager::register(
            JWT::class
        );

        //Set method to fetch user object, including password attribute
        \Phramework\Authentication\Manager::setUserGetByEmailMethod(
            [JWTTest::class, 'getByEmailWithPassword']
        );

        \Phramework\Authentication\Manager::setAttributes(
            ['user_type', 'email']
        );

        \Phramework\Authentication\Manager::setOnCheckCallback(
            /**
             * @param object $data User data object
             */
            function ($params) {
                //var_dump($params);
            }
        );

        \Phramework\Authentication\Manager::setOnAuthenticateCallback(
            /**
             * @param object $data User data object
             */
            function ($params) {
                //var_dump($params);
            }
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
     * @covers Phramework\Authentication\JWT\JWT::check
     */
    public function testCheckFailure()
    {
        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            []
        ), 'Expect false, since Authorization header is not provided');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Basic ABCDEF']
        ), 'Expect false, since Authorization header is not Bearer');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer xsadsadas']
        ), 'Expect false, since token makes no sense');

        $this->assertFalse($this->object->check(
            [],
            Phramework::METHOD_GET,
            [
                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                    . 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW'
                    . '4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
            ]
        ), 'Expect false, since token is not correct');
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::testProvidedMethod
     */
    public function testTestProvidedMethodFailure()
    {
        $this->assertFalse($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            []
        ), 'Expect false, since Authorization header is not provided');

        $this->assertFalse($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Basic ABCDEF']
        ), 'Expect false, since Authorization header is not Bearer');
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::testProvidedMethod
     */
    public function testTestProvidedMethodSuccess()
    {
        $this->assertTrue($this->object->testProvidedMethod(
            [],
            Phramework::METHOD_GET,
            ['Authorization' => 'Bearer zm9ocG9uZXsg6MTIzNDU2Nzh4WA==']
        ), 'Expect true, even though credentials are not correct');
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::authenticate
     * @expectedException Exception
     */
    public function testAuthenticateExpectException()
    {
        $this->object->authenticate(
            [
                'email' => 'wrongEmailType',
                'password' => '123456'
            ],
            [Phramework::METHOD_POST],
            []
        );
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::authenticate
     */
    public function testAuthenticateFailure()
    {
        $this->assertFalse(
            $this->object->authenticate(
                [
                    'email' => 'not@found.com',
                    'password' => '123456'
                ],
                Phramework::METHOD_POST,
                []
            ),
            'Expect false, sinse user email doesn`t exist'
        );

        $this->assertFalse(
            $this->object->authenticate(
                [
                    'email' => self::$users[0]['email'],
                    'password' => 'wrong'
                ],
                Phramework::METHOD_POST,
                []
            ),
            'Expect false, sinse user password is wrong'
        );
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::authenticate
     */
    public function testAuthenticateSuccess()
    {
        //Pick a random user index
        $index = 0; //rand(0, count(self::$users) - 1);

        list($user, $token) = $this->object->authenticate(
            [
                'email' => self::$users[$index]['email'],
                'password' => '123456' //Since password is the same for all of them
            ],
            Phramework::METHOD_POST,
            []
        );

        $this->assertInternalType('object', $user, 'Expect an object');

        $this->assertObjectHasAttribute('id', $user);
        $this->assertObjectHasAttribute('email', $user);
        $this->assertObjectHasAttribute('user_type', $user);
        $this->assertObjectNotHasAttribute('password', $user);

        $this->assertSame(self::$users[$index]['id'], $user->id);
        $this->assertSame(self::$users[$index]['email'], $user->email);
        $this->assertSame(self::$users[$index]['user_type'], $user->user_type);

        return [$index, $user, $token];
    }

    /**
     * @covers Phramework\Authentication\JWT\JWT::check
     * @depends testAuthenticateSuccess
     */
    public function testCheckSuccess($indexToken)
    {
        list($index, $user, $token) = $indexToken;

        $user = $this->object->check(
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
