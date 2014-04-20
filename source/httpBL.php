<?php
/**
 * httpBL
 *
 * Generator for Project Honeypot BL service requests
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
 * httpBL
 *
 * Generator for Project Honeypot BL service requests
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
class httpBL {

	/**
	 * API key for Project Honey pot; 12 alpha characters, lower-case
	 * @access private
	 * @var string
	 */
	protected $apiKey;

	/**
	 * Class to create for Project Honeypot http::BL response
	 * @access private
	 * @var string
	 */
	protected $responseClass = 'WSIServices\\httpBL\\response';

	/**
	 * Construct httpBL class with http::BL API key
	 * @access public
	 * @param string $apiKey API key for Project Honey pot; 12 alpha characters, lower-case
	 * @throws InvalidArgumentException
	 *
	 * @example
	 * <code>
	 * $httpBL = new httpBL('abcdefghijkl');
	 * </code>
	 */
	public function __construct($apiKey) {
		if(!preg_match('/^[a-z]{12}$/', $apiKey)) {
			throw new \InvalidArgumentException('The value provided is not a valid API Key for Project Honeypot.');
		}

		$this->apiKey = $apiKey;
	}

	/**
	 * Return response object for specified IP address
	 * @access public
	 * @param  string $ipAddress IP address to look up with http::BL
	 * @return object            Response object for specified IP address
	 *
	 * @example
	 * <code>
	 * $response = $httpBL->lookup('127.1.1.1');
	 * </code>
	 */
	public function lookup($ipAddress) {
		if(!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
			throw new \InvalidArgumentException('The value provided is not a valid IPv4 address.');
		}

		return new $this->responseClass($this->apiKey, $ipAddress);
	}

	/**
	 * Return configured API key for Project Honeypot
	 * @access public
	 * @return string API key for Project Honey pot; 12 alpha characters, lower-case
	 *
	 * @example
	 * <code>
	 * $apiKey = $httpBL->getApiKey();
	 * </code>
	 */
	public function getApiKey() {
		return $this->apiKey;
	}

	/**
	 * Return configured response class name
	 * @access public
	 * @return string Name of response class to use for generating response objects
	 *
	 * @example
	 * <code>
	 * $responseClass = $httpBL->getResponseClass();
	 * </code>
	 */
	public function getResponseClass() {
		return $this->responseClass;
	}

	/**
	 * Set response class name configuration
	 * @access public
	 * @param string $className Valid class name for generating response objects
	 *
	 * @example
	 * <code>
	 * $httpBL->setResponseClass('WSIServices\httpBL\responseMock');
	 * </code>
	 */
	public function setResponseClass($className) {
		if(!class_exists($className)) {
			throw new \InvalidArgumentException('The value provided is not a valid class name.');
		}

		$this->responseClass = $className;
	}
}