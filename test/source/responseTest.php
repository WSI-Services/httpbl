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
 * responseTest
 * @since 0.1.0
 * @coversDefaultClass WSIServices\httpBL\response
 */
class responseTest extends \PHPUnit_Framework_TestCase {

	/**
	 * @var response
	 */
	protected $response;

	/**
	 * Sets up the fixture, for example, opens a network connection.
	 * This method is called before a test is executed.
	 */
	protected function setUp() {
		$this->response = new response('abcdefghijkl', '127.0.0.1');

		$this->mockDnsARecord = $this->getMock(
			'WSIServices\httpBL\response',
			array('getDnsARecord'),
			array('abcdefghijkl', '127.0.0.1')
		);
	}

	/**
	 * Tears down the fixture, for example, closes a network connection.
	 * This method is called after a test is executed.
	 */
	protected function tearDown() {
		$this->response = null;
		$this->mockDnsARecord = null;
	}

	/**
	 * Get DNS A Record return value
	 * @param string $ipAddress IP address to use in DNS response
	 */
	public function getDnsARecord($ipAddress = null, $ttl = 0) {
		if(null == $ipAddress) {
			$returnValue = array();
		} else {
			$reversIpAddress = implode('.', array_reverse(explode('.', $ipAddress)));
			$returnValue = array(array(
				'host' => 'abcdefghijkl.'.$reversIpAddress.'.dnsbl.httpbl.org',
				'class' => 'IN',
				'ttl' => $ttl,
				'type' => 'A',
				'ip' => $ipAddress
			));
		}

		return $returnValue;
	}

	/**
	 * Set Mock getDnsARecord return value
	 * @param string $ipAddress IP address to use in DNS response
	 */
	public function setMockDnsARecordIp($ipAddress = null, $ttl = 0) {
		$this->mockDnsARecord
			->expects($this->once())
			->method('getDnsARecord')
			->will($this->returnValue($this->getDnsARecord($ipAddress, $ttl)));
	}

	/**
	 * @covers ::__construct()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid API Key for Project Honeypot.
	 */
	public function testConstructWithInvalidKey() {
		$response = new response('abcd1234', '127.0.0.1');
	
		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::__construct()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 */
	public function testConstructWithInvalidIp4Address() {
		$response = new response('abcdefghijkl', '256.1.2.3');
	
		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::__construct()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 */
	public function testConstructWithPrivateRangeIp() {
		$response = new response('abcdefghijkl', '192.168.1.1');
	
		$this->fail('This test should have thrown an InvalidArgumentException.');
	}

	/**
	 * @covers ::__construct()
	 * @expectedException        \InvalidArgumentException
	 * @expectedExceptionMessage The value provided is not a valid IPv4 address.
	 */
	public function testConstructWithIp6Address() {
		$response = new response('abcdefghijkl', '::1');
	
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
			$this->response->getApiKey(),
			'The API Key is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getIpAddress()
	 *
	 * @covers ::__construct()
	 */
	public function testGetIpAddress() {
		$this->assertSame(
			'127.0.0.1',
			$this->response->getIpAddress(),
			'The IP Address is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getRawRequest()
	 *
	 * @covers ::__construct()
	 */
	public function testGetRawRequest() {
		$request = $this->response->getRawRequest();

		$this->assertStringStartsWith(
			'abcdefghijkl.',
			$request,
			'The Raw Request does not start with the API Key.'
		);

		$this->assertStringEndsWith(
			'.dnsbl.httpbl.org',
			$request,
			'The Raw Request does not end with HttpBL Black List domain.'
		);

		$this->assertContains(
			'.1.0.0.127.',
			$request,
			'The Raw Request does not contain the requested IP.'
		);
	}

	/**
	 * @covers ::getDnsARecord()
	 * @covers ::getRawResponse()
	 *
	 * @covers ::__construct()
	 */
	public function testGetDnsARecord() {
		$domainName = 'google-public-dns-b.google.com';
		$ipAddress = '8.8.4.4';

		$mock = $this->getMock(
			'WSIServices\httpBL\response',
			array('getRawRequest'),
			array('abcdefghijkl', $ipAddress)
		);

		$mock->expects($this->once())
			->method('getRawRequest')
			->will($this->returnValue($domainName));

			$response = $mock->getRawResponse();

		$this->assertSame(
			array(
				$domainName,
				$ipAddress
			),
			array(
				$response[0]['host'],
				$response[0]['ip']
			),
			'The Raw Response is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getRawResponse()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 */
	public function testGetRawResponse() {
		$this->setMockDnsARecordIp('127.1.1.1');

		$this->assertSame(
			array(array(
				'host' => 'abcdefghijkl.1.1.1.127.dnsbl.httpbl.org',
				'class' => 'IN',
				'ttl' => 0,
				'type' => 'A',
				'ip' => '127.1.1.1'
			)),
			$this->mockDnsARecord->getRawResponse(),
			'The Raw Response is not being returned correctly.'
		);
	}

	/**
	 * @covers ::inBlacklist()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 */
	public function testInBlacklistReturningTrue() {
		$this->setMockDnsARecordIp('127.1.1.1');

		$this->assertTrue(
			$this->mockDnsARecord->inBlacklist(),
			'The DNS information is not being interpreted correctly.'
		);
	}

	/**
	 * @covers ::inBlacklist()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 */
	public function testInBlacklistReturningFalse() {
		$this->setMockDnsARecordIp();

		$this->assertFalse(
			$this->mockDnsARecord->inBlacklist(),
			'The DNS information is not being interpreted correctly.'
		);
	}

	/**
	 * @covers ::getTtl()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTtl() {
		$ttl = rand(300, 86400);

		$this->setMockDnsARecordIp('127.0.0.1', $ttl);

		$this->assertSame(
			$ttl,
			$this->mockDnsARecord->getTtl(),
			'The TTL information is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getTtl()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTtlReturningNoResponse() {
		$this->setMockDnsARecordIp();

		$this->assertNull(
			$this->mockDnsARecord->getTtl(),
			'The TTL information is not being returned correctly.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningSearchEngine() {
		$this->setMockDnsARecordIp('127.1.1.0');

		$this->assertSame(
			response::VISITOR_SEARCH_ENGINE,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Search Engine.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningSuspicious() {
		$this->setMockDnsARecordIp('127.1.1.1');

		$this->assertSame(
			response::VISITOR_SUSPICIOUS,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Suspicious.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningHarvester() {
		$this->setMockDnsARecordIp('127.1.1.2');

		$this->assertSame(
			response::VISITOR_HARVESTER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Harvester.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningSuspiciousHarvester() {
		$this->setMockDnsARecordIp('127.1.1.3');

		$this->assertSame(
			response::VISITOR_SUSPICIOUS
				| response::VISITOR_HARVESTER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Suspicious & Harvester.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningCommentSpamer() {
		$this->setMockDnsARecordIp('127.1.1.4');

		$this->assertSame(
			response::VISITOR_COMMENT_SPAMER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Comment Spamer.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningSuspiciousCommentSpamer() {
		$this->setMockDnsARecordIp('127.1.1.5');

		$this->assertSame(
			response::VISITOR_SUSPICIOUS
				| response::VISITOR_COMMENT_SPAMER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Suspicious & CommentSpamer.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningHarvesterCommentSpamer() {
		$this->setMockDnsARecordIp('127.1.1.6');

		$this->assertSame(
			response::VISITOR_HARVESTER
				| response::VISITOR_COMMENT_SPAMER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Harvester & CommentSpamer.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningSuspiciousHarvesterCommentSpamer() {
		$this->setMockDnsARecordIp('127.1.1.7');

		$this->assertSame(
			response::VISITOR_SUSPICIOUS
				| response::VISITOR_HARVESTER
				| response::VISITOR_COMMENT_SPAMER,
			$this->mockDnsARecord->getType(),
			'The visitor type was not returned as Suspicious & Harvester & CommentSpamer.'
		);
	}

	/**
	 * @covers ::getType()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetTypeReturningNone() {
		$this->setMockDnsARecordIp();

		$this->assertNull(
			$this->mockDnsARecord->getType(),
			'A visitor type was returned and should not have.'
		);
	}

	/**
	 * @covers ::getTypeName()
	 *
	 * @covers ::__construct()
	 */
	public function testGetTypeName() {
		$tests = array(
			'Search Engine',
			'Suspicious',
			'Harvester',
			'Suspicious & Harvester',
			'Comment Spamer',
			'Suspicious & Comment Spamer',
			'Harvester & Comment Spamer',
			'Suspicious & Harvester & Comment Spamer',
		);

		foreach ($tests as $type => $name) {
			$this->assertSame(
				$name,
				$this->response->getTypeName($type),
				'The visitor type name was not returned as '.$name.'.'
			);
		}
	}

	/**
	 * @covers ::getThreatScore()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetThreatScore() {
		$this->setMockDnsARecordIp('127.16.123.3');

		$this->assertSame(
			123,
			$this->mockDnsARecord->getThreatScore(),
			'The threat score was not returned correctly.'
		);
	}

	/**
	 * @covers ::getThreatScore()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetThreatScoreReturningNone() {
		$this->setMockDnsARecordIp();

		$this->assertNull(
			$this->mockDnsARecord->getThreatScore(),
			'The threat score was not returned correctly.'
		);
	}

	/**
	 * @covers ::getLastActive()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetLastActive() {
		$this->setMockDnsARecordIp('127.16.123.3');

		$this->assertSame(
			16,
			$this->mockDnsARecord->getLastActive(),
			'The last active was not returned correctly.'
		);
	}

	/**
	 * @covers ::getLastActive()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 */
	public function testGetLastActiveReturningNone() {
		$this->setMockDnsARecordIp();

		$this->assertNull(
			$this->mockDnsARecord->getLastActive(),
			'The last active was not returned correctly.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningUndocumented() {
		$this->setMockDnsARecordIp('127.0.0.0');

		$this->assertSame(
			response::SEARCH_ENGINE_UNDOCUMENTED,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Undocumented.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningAltaVista() {
		$this->setMockDnsARecordIp('127.0.1.0');

		$this->assertSame(
			response::SEARCH_ENGINE_ALTAVISTA,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as AltaVista.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningAsk() {
		$this->setMockDnsARecordIp('127.0.2.0');

		$this->assertSame(
			response::SEARCH_ENGINE_ASK,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Ask.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningBaidu() {
		$this->setMockDnsARecordIp('127.0.3.0');

		$this->assertSame(
			response::SEARCH_ENGINE_BAIDU,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Baidu.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningExcite() {
		$this->setMockDnsARecordIp('127.0.4.0');

		$this->assertSame(
			response::SEARCH_ENGINE_EXCITE,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Excite.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningGoogle() {
		$this->setMockDnsARecordIp('127.0.5.0');

		$this->assertSame(
			response::SEARCH_ENGINE_GOOGLE,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Google.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningLookSmart() {
		$this->setMockDnsARecordIp('127.0.6.0');

		$this->assertSame(
			response::SEARCH_ENGINE_LOOKSMART,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as LookSmart.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningLycos() {
		$this->setMockDnsARecordIp('127.0.7.0');

		$this->assertSame(
			response::SEARCH_ENGINE_LYCOS,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Lycos.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningMSN() {
		$this->setMockDnsARecordIp('127.0.8.0');

		$this->assertSame(
			response::SEARCH_ENGINE_MSN,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as MSN.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningYahoo() {
		$this->setMockDnsARecordIp('127.0.9.0');

		$this->assertSame(
			response::SEARCH_ENGINE_YAHOO,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Yahoo.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningCuil() {
		$this->setMockDnsARecordIp('127.0.10.0');

		$this->assertSame(
			response::SEARCH_ENGINE_CUIL,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Cuil.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningInfoSeek() {
		$this->setMockDnsARecordIp('127.0.11.0');

		$this->assertSame(
			response::SEARCH_ENGINE_INFOSEEK,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as InfoSeek.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningMiscellaneous() {
		$this->setMockDnsARecordIp('127.0.12.0');

		$this->assertSame(
			response::SEARCH_ENGINE_MISCELLANEOUS,
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was not returned as Miscellaneous.'
		);
	}

	/**
	 * @covers ::getSearchEngine()
	 *
	 * @covers ::__construct()
	 * @covers ::getRawRequest()
	 * @covers ::getRawResponse()
	 * @covers ::inBlacklist()
	 * @covers ::getType()
	 */
	public function testGetSearchEngineReturningNone() {
		$this->setMockDnsARecordIp();

		$this->assertNull(
			$this->mockDnsARecord->getSearchEngine(),
			'The search engine was returned and should not have.'
		);
	}

	/**
	 * @covers ::getSearchEngineName()
	 *
	 * @covers ::__construct()
	 */
	public function testGetSearchEngineName() {
		$tests = array(
			0	=> 'Undocumented',
			1	=> 'AltaVista',
			2	=> 'Ask',
			3	=> 'Baidu',
			4	=> 'Excite',
			5	=> 'Google',
			6	=> 'Looksmart',
			7	=> 'Lycos',
			8	=> 'MSN',
			9	=> 'Yahoo',
			10	=> 'Cuil',
			11	=> 'InfoSeek',
			12	=> 'Miscellaneous',
		);

		foreach ($tests as $type => $name) {
			$this->assertSame(
				$name,
				$this->response->getSearchEngineName($type),
				'The search engine name was not returned as '.$name.'.'
			);
		}
	}

	/**
	 * @covers ::getSearchEngineName()
	 *
	 * @covers ::__construct()
	 */
	public function testGetSearchEngineNameReturningNone() {
		$this->assertNull(
			$this->response->getSearchEngineName(null),
			'The search engine name was returned and should not have.'
		);
	}
}