<?php
/**
 * response
 *
 * Request response object for calls to Project Honeypot BL
 *
 * @package httpBL
 * @version 0.1.0
 * @copyright WSI-Services 2014
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
 * response
 *
 * Request response object for calls to Project Honeypot BL
 *
 * @since 0.1.0
 *
 * @example
 * <code>
 * $blackList = new WSIServices\httpBL\httpBL($apiKey);
 * <br>
 * $response = $blackList->lookup($clientIp);
 * </code>
 */
class response {

	CONST VISITOR_SEARCH_ENGINE  = 0;
	CONST VISITOR_SUSPICIOUS     = 1;
	CONST VISITOR_HARVESTER      = 2;
	CONST VISITOR_COMMENT_SPAMER = 4;

	CONST SEARCH_ENGINE_UNDOCUMENTED  = 0;
	CONST SEARCH_ENGINE_ALTAVISTA     = 1;
	CONST SEARCH_ENGINE_ASK           = 2;
	CONST SEARCH_ENGINE_BAIDU         = 3;
	CONST SEARCH_ENGINE_EXCITE        = 4;
	CONST SEARCH_ENGINE_GOOGLE        = 5;
	CONST SEARCH_ENGINE_LOOKSMART     = 6;
	CONST SEARCH_ENGINE_LYCOS         = 7;
	CONST SEARCH_ENGINE_MSN           = 8;
	CONST SEARCH_ENGINE_YAHOO         = 9;
	CONST SEARCH_ENGINE_CUIL          = 10;
	CONST SEARCH_ENGINE_INFOSEEK      = 11;
	CONST SEARCH_ENGINE_MISCELLANEOUS = 12;

	/**
	 * API key for Project Honey pot; 12 alpha characters, lower-case
	 * @access private
	 * @var string
	 */
	protected $apiKey;

	/**
	 * IP address to query
	 * @access private
	 * @var string
	 */
	protected $ipAddress;

	/**
	 * Request used to query
	 * @access private
	 * @var string
	 */
	protected $rawRequest;

	/**
	 * Response returned from query
	 * @access private
	 * @var array
	 */
	protected $rawResponse;

	/**
	 * Parsed response returned from query
	 * @access private
	 * @var array
	 */
	protected $response;

	/**
	 * Returned response time-to-live
	 * @access private
	 * @var integer
	 */
	protected $responseTtl;

	/**
	 * Returned visitor type
	 * @access private
	 * @var integer
	 */
	protected $visitorType;

	/**
	 * Returned threat score
	 * @access private
	 * @var integer
	 */
	protected $threatScore;

	/**
	 * Returned last active
	 * @access private
	 * @var integer
	 */
	protected $lastActive;

	/**
	 * List of visitor types
	 * @access private
	 * @var array
	 */
	protected $visitorTypes = array(
		4 => 'Comment Spamer',
		2 => 'Harvester',
		1 => 'Suspicious',
		0 => 'Search Engine',
	);

	/**
	 * Returned search engine
	 * @access private
	 * @var integer
	 */
	protected $searchEngine;

	/**
	 * List of search engines
	 * @access private
	 * @var array
	 */
	protected $searchEngines = array(
		12	=> 'Miscellaneous',
		11	=> 'InfoSeek',
		10	=> 'Cuil',
		9	=> 'Yahoo',
		8	=> 'MSN',
		7	=> 'Lycos',
		6	=> 'Looksmart',
		5	=> 'Google',
		4	=> 'Excite',
		3	=> 'Baidu',
		2	=> 'Ask',
		1	=> 'AltaVista',
		0	=> 'Undocumented',
	);

	/**
	 * Construct response class with http::BL API key and IP address
	 * @access public
	 * @param string $apiKey    API key for Project Honey pot; 12 alpha characters, lower-case
	 * @param string $ipAddress IP address to query
	 *
	 * @example
	 * <code>
	 * $response = new WSIServices\httpBL\response('abcdefghijkl', '127.1.1.1');
	 * </code>
	 */
	public function __construct($apiKey, $ipAddress) {
		if(!preg_match('/^[a-z]{12}$/', $apiKey)) {
			throw new \InvalidArgumentException('The value provided is not a valid API Key for Project Honeypot.');
		}

		$this->apiKey = $apiKey;

		if(!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
			throw new \InvalidArgumentException('The value provided is not a valid IPv4 address.');
		}

		$this->ipAddress = $ipAddress;
	}

	/**
	 * Return the API key in use
	 * @access public
	 * @return string API key for Project Honey pot; 12 alpha characters, lower-case
	 *
	 * @example
	 * <code>
	 * $apiKey = $response->getApiKey();
	 * </code>
	 */
	public function getApiKey() {
		return $this->apiKey;
	}

	/**
	 * Return the IP address queried
	 * @access public
	 * @return string IP address queried
	 *
	 * @example
	 * <code>
	 * $ipAddress = $response->getIpAddress();
	 * </code>
	 */
	public function getIpAddress() {
		return $this->ipAddress;
	}

	/**
	 * Return request used to query
	 * @access public
	 * @return string Request used to query
	 *
	 * @example
	 * <code>
	 * $rawRequest = $response->getRawRequest();
	 * </code>
	 */
	public function getRawRequest() {
		if(null == $this->rawRequest) {
			$this->rawRequest = $this->apiKey.'.'
				.implode(
					'.',
					array_reverse(
						explode('.', $this->ipAddress)
					)
				)
				.'.dnsbl.httpbl.org';
		}

		return $this->rawRequest;
	}

	/**
	 * Return DNS A record for provided hostname
	 * @access private
	 * @param  string $hostname Hostname to query DNS
	 * @return array            DNS A record
	 * @codeCoverageIgnore
	 */
	protected function getDnsARecord($hostname) {
		return dns_get_record($hostname, DNS_A);
	}

	/**
	 * Return DNS A record response 
	 * @access public
	 * @return array DNS A record
	 *
	 * @example
	 * <code>
	 * $rawResponse = $response->getRawResponse();
	 * </code>
	 */
	public function getRawResponse() {
		if(null == $this->rawResponse) {
			$this->rawResponse = $this->getDnsARecord($this->getRawRequest());
		}

		return $this->rawResponse;
	}

	/**
	 * Check if queried IP address is in blacklist
	 * @access public
	 * @return boolean True if IP address was recognized
	 *
	 * @example
	 * <code>
	 * $inBlacklist = $response->inBlacklist();
	 * </code>
	 */
	public function inBlacklist() {
		if(null == $this->response) {
			if(null == $this->rawResponse) {
				$this->getRawResponse();
			}

			if(count($this->rawResponse) > 0
				&& array_key_exists('ip', $this->rawResponse[0])
			) {
				$this->response = explode('.', $this->rawResponse[0]['ip']);
				if($this->response[0] != '127')
					$this->response = false;
				else
					foreach ($this->response as &$value)
						$value = (int) $value;
			}
		}

		return is_array($this->response);
	}

	/**
	 * Return response time-to-live
	 * @return integer Response lifespan in seconds
	 *
	 * @example
	 * <code>
	 * $responseTtl = $response->getTtl();
	 * </code>
	 */
	public function getTtl() {
		if(null == $this->responseTtl) {
			if($this->inBlacklist()) {
				$this->responseTtl = $this->rawResponse[0]['ttl'];
			}
		}

		return $this->responseTtl;
	}

	/**
	 * Return visitor type id
	 * @access public
	 * @return integer Visitor type
	 *
	 * @example
	 * <code>
	 * $visitorType = $response->getType();
	 * </code>
	 */
	public function getType() {
		if(null == $this->visitorType) {
			if($this->inBlacklist()) {
				$this->visitorType = $this->response[3];
			}
		}

		return $this->visitorType;
	}

	/**
	 * Return visitor type name
	 * @access public
	 * @param  integer $visitorType Visitor type id
	 * @return string               Visitor type name
	 *
	 * @example
	 * <code>
	 * $visitorTypeName = $response->getTypeName($visitorType);
	 * </code>
	 */
	public function getTypeName($visitorType) {
		$types = array();
		$visitorTypes = $this->visitorTypes;
		$search = array_pop($visitorTypes);

		foreach($visitorTypes as $id => $name) {
			if($visitorType >= $id) {
				$visitorType -= $id;
				$types[] = $name;
			}
		}

		if(count($types) == 0) {
			$types = $search;
		} else {
			$types = implode(' & ', array_reverse($types));
		}

		return $types;
	}

	/**
	 * Return threat score
	 * @access public
	 * @return integer Visitor threat score
	 *
	 * @example
	 * <code>
	 * $threatScore = $response->getThreatScore();
	 * </code>
	 */
	public function getThreatScore() {
		if(null == $this->threatScore) {
			if($this->inBlacklist()
				&& $this->getType() !== response::VISITOR_SEARCH_ENGINE
			) {
				$this->threatScore = $this->response[2];
			} else {
				$this->threatScore = null;
			}
		}

		return $this->threatScore;
	}

	/**
	 * Return last active
	 * @access public
	 * @return integer Visitor last active
	 *
	 * @example
	 * <code>
	 * $lastActive = $response->getLastActive();
	 * </code>
	 */
	public function getLastActive() {
		if(null == $this->lastActive) {
			if($this->inBlacklist()
				&& $this->getType() !== response::VISITOR_SEARCH_ENGINE
			) {
				$this->lastActive = $this->response[1];
			} else {
				$this->lastActive = null;
			}
		}

		return $this->lastActive;
	}

	/**
	 * Return search engine id
	 * @access public
	 * @return integer Search engine id
	 *
	 * @example
	 * <code>
	 * $searchEngine = $response->getSearchEngine();
	 * </code>
	 */
	public function getSearchEngine() {
		if(null == $this->searchEngine) {
			if($this->getType() === response::VISITOR_SEARCH_ENGINE) {
				$this->searchEngine = $this->response[2];
			} else {
				$this->searchEngine = null;
			}
		}

		return $this->searchEngine;
	}

	/**
	 * Return search engine name
	 * @access public
	 * @param  integer $searchEngine Search engine id
	 * @return string                Search engine name
	 *
	 * @example
	 * <code>
	 * $searchEngineName = $response->getSearchEngineName($searchEngine);
	 * </code>
	 */
	public function getSearchEngineName($searchEngine) {
		if(array_key_exists($searchEngine, $this->searchEngines)) {
			return $this->searchEngines[$searchEngine];
		}
	}
}