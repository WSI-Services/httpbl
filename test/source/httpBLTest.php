<?php
/**
 * @package httpBL
 * @version 0.1.0
 * @copyright Copyright (c) 2014, WSI-Services
 *
 * @author Sam Likins <sam.likins@wsi-services.com>
 * @link http://wsi-services.com
 *
 * @license http://opensource.org/licenses/gpl-3.0.html
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

namespace WSIServices\httpBL;

/**
 * httpBLTest
 * @since 0.1.0
 * @coversDefaultClass WSIServices\httpBL\httpBL
 */
class httpBLTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var httpBL
	 */
	protected $httpBL;

	/**
	 * This method is called before a test is executed.
	 */
	protected function setUp() {
		$this->httpBL = new httpBL('abcdefghijkl');
	}

	/**
	 * Tears down the fixture, for example, closes a network connection.
	 * This method is called after a test is executed.
	 */
	protected function tearDown() {
		$this->httpBL = null;
	}

	/**
	 * @covers ::__construct()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid API Key for Project Honeypot.
	 */
	public function testConstructWithInvalidKey() {
		$httpBL = new httpBL('abcd1234');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::lookup()
	 *
	 * @covers ::__construct()
	 * @covers ::getResponseClass()
	 * @covers ::setResponseClass()
	 */
	public function testLookup() {
		$this->httpBL->setResponseClass('WSIServices\httpBL\responseMock');
		$this->assertSame(
			'WSIServices\httpBL\responseMock',
			$this->httpBL->getResponseClass(),
			'The Response class is not being set correctly.'
		);

		$response = $this->httpBL->lookup('127.0.0.1');

		$this->assertInternalType(
			'object',
			$response,
			'Lookup should have returned an object type.'
		);

		$this->assertInstanceOf(
			'WSIServices\httpBL\responseMock',
			$response,
			'Lookup should have returned a responseMock object.'
		);

		$this->assertSame(
			'abcdefghijkl',
			$response->apiKey,
			'The lookup response should have contained another API key.'
		);

		$this->assertSame(
			'127.0.0.1',
			$response->ipAddress,
			'The lookup response should have contained another IP address.'
		);
	}

	/**
	 * @covers ::lookup()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 *
	 * @covers ::__construct()
	 */
	public function testLookupWithInvalidIp4Address() {
		$this->httpBL->lookup('256.1.2.3');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::lookup()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 *
	 * @covers ::__construct()
	 */
	public function testLookupWithPrivateRangeIp() {
		$this->httpBL->lookup('192.168.1.1');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::lookup()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 *
	 * @covers ::__construct()
	 */
	public function testLookupWithIp6Address() {
		$this->httpBL->lookup('::1');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::getApiKey()
	 *
	 * @covers ::__construct()
	 */
	public function testGetApiKey() {
		$this->assertSame(
			'abcdefghijkl',
			$this->httpBL->getApiKey(),
			'The API Key is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getResponseClass()
	 *
	 * @covers ::__construct()
	 */
	public function testGetResponseClass() {
		$this->assertSame(
			'WSIServices\httpBL\response',
			$this->httpBL->getResponseClass(),
			'The Response class is not being returned correctly.'
		);
	}

	/**
	 * @covers ::setResponseClass()
	 *
	 * @covers ::__construct()
	 * @covers ::getResponseClass()
	 */
	public function testSetResponseClass() {
		$this->httpBL->setResponseClass('WSIServices\httpBL\responseMock');

		$this->assertSame(
			'WSIServices\httpBL\responseMock',
			$this->httpBL->getResponseClass(),
			'The Response class is not being set correctly.'
		);
	}

	/**
	 * @covers ::setResponseClass()
	 * @expectedException        InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid class name.
	 *
	 * @covers ::__construct()
	 */
	public function testSetResponseClassWithEmptyString() {
		$this->httpBL->setResponseClass('');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::setResponseClass()
	 * @expectedException        InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid class name.
	 *
	 * @covers ::__construct()
	 */
	public function testSetResponseClassWithInvalidName() {
		$this->httpBL->setResponseClass('WSIServices\Test\Fail\0Test');

		$this->fail('This test should have thrown an InvalidArgumentException.');
	}
}