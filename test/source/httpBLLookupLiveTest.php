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

define('WSIServices\httpBL\PROJECT_HONEYPOT_API_KEY', 'abcdefghijkl');

/**
 * httpBLLookupLiveTest
 * @since 0.1.0
 * @group LiveTests
 */
class httpBLLookupLiveTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var httpBL
	 */
	protected $httpBL;

	/**
	 * Simulated query response pairs
	 * @var array
	 */
	protected $simulatedQueryResponse = array(
		'types' => array(
			'127.1.1.0',
			'127.1.1.1',
			'127.1.1.2',
			'127.1.1.3',
			'127.1.1.4',
			'127.1.1.5',
			'127.1.1.6',
			'127.1.1.7',
		),
		'threatLevels' => array(
			'127.1.10.1',
			'127.1.20.1',
			'127.1.40.1',
			'127.1.80.1',
		),
		'numberOfDays' => array(
			'127.10.1.1',
			'127.20.1.1',
			'127.40.1.1',
			'127.80.1.1',
		),
	);

	/**
	 * Sets up the fixture, for example, opens a network connection.
	 * This method is called before a test is executed.
	 */
	public function setUp() {
		$this->httpBL = new httpBL(PROJECT_HONEYPOT_API_KEY);
	}


	/**
	 * Tears down the fixture, for example, closes a network connection.
	 * This method is called after a test is executed.
	 */
	public function tearDown() {
		$this->httpBL = null;
	}

	/**
	 * Generate expected DNS A record response
	 * @param  string $ipAddress IP address to generate response for
	 * @return array             Array containing expected DNS A record response
	 */
	protected function generateResponse($ipAddress) {
		if('127.0.0.1' == $ipAddress) {
			$returnValue = array();
		} else {
			$returnValue = array(array(
				'host' => PROJECT_HONEYPOT_API_KEY.'.'
					.implode('.', array_reverse(explode('.', $ipAddress)))
					.'.dnsbl.httpbl.org',
				'class' => 'IN',
				'ttl' => 0,
				'type' => 'A',
				'ip' => $ipAddress
			));
		}

		return $returnValue;
	}

	/**
	 * @covers WSIServices\httpBL\httpBL::lookup()
	 *
	 * @covers WSIServices\httpBL\httpBL::__construct()
	 * @covers WSIServices\httpBL\response::__construct()
	 * @covers WSIServices\httpBL\response::getRawRequest()
	 * @covers WSIServices\httpBL\response::getRawResponse()
	 */
	public function testLookupNoRecordFound() {
		$response = $this->httpBL->lookup('127.0.0.1');

		$this->assertSame(
			$this->generateResponse('127.0.0.1'),
			$response->getRawResponse(),
			'Lookup with no record should return NXDOMAIN'
		);
	}

	/**
	 * @covers WSIServices\httpBL\httpBL::lookup()
	 *
	 * @covers WSIServices\httpBL\httpBL::__construct()
	 * @covers WSIServices\httpBL\response::__construct()
	 * @covers WSIServices\httpBL\response::getRawRequest()
	 * @covers WSIServices\httpBL\response::getRawResponse()
	 */
	public function testLookupTypes() {
		foreach ($this->simulatedQueryResponse['types'] as $lookup) {
			$response = $this->httpBL->lookup($lookup);
			$rawResponse = $response->getRawResponse();

			$expectedResponse = $this->generateResponse($lookup);

			$this->assertSame(
				$expectedResponse[0]['host'],
				$rawResponse[0]['host'],
				'Lookup of '.$lookup.' should return Host '.$expectedResponse[0]['host']
			);

			$this->assertSame(
				$expectedResponse[0]['ip'],
				$rawResponse[0]['ip'],
				'Lookup of '.$lookup.' should return IP '.$expectedResponse[0]['ip']
			);
		}
	}

	/**
	 * @covers WSIServices\httpBL\httpBL::lookup()
	 *
	 * @covers WSIServices\httpBL\httpBL::__construct()
	 * @covers WSIServices\httpBL\response::__construct()
	 * @covers WSIServices\httpBL\response::getRawRequest()
	 * @covers WSIServices\httpBL\response::getRawResponse()
	 */
	public function testLookupThreatLevels() {
		foreach ($this->simulatedQueryResponse['threatLevels'] as $lookup) {
			$response = $this->httpBL->lookup($lookup);
			$rawResponse = $response->getRawResponse();

			$expectedResponse = $this->generateResponse($lookup);

			$this->assertSame(
				$expectedResponse[0]['host'],
				$rawResponse[0]['host'],
				'Lookup of '.$lookup.' should return host '.$expectedResponse[0]['host']
			);

			$this->assertSame(
				$expectedResponse[0]['ip'],
				$rawResponse[0]['ip'],
				'Lookup of '.$lookup.' should return IP '.$expectedResponse[0]['ip']
			);
		}
	}

	/**
	 * @covers WSIServices\httpBL\httpBL::lookup()
	 *
	 * @covers WSIServices\httpBL\httpBL::__construct()
	 * @covers WSIServices\httpBL\response::__construct()
	 * @covers WSIServices\httpBL\response::getRawRequest()
	 * @covers WSIServices\httpBL\response::getRawResponse()
	 */
	public function testLookupNumberOfDays() {
		foreach ($this->simulatedQueryResponse['numberOfDays'] as $lookup) {
			$response = $this->httpBL->lookup($lookup);
			$rawResponse = $response->getRawResponse();

			$expectedResponse = $this->generateResponse($lookup);

			$this->assertSame(
				$expectedResponse[0]['host'],
				$rawResponse[0]['host'],
				'Lookup of '.$lookup.' should return host '.$expectedResponse[0]['host']
			);

			$this->assertSame(
				$expectedResponse[0]['ip'],
				$rawResponse[0]['ip'],
				'Lookup of '.$lookup.' should return IP '.$expectedResponse[0]['ip']
			);
		}
	}
}