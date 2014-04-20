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
 * responseMock
 * @since 0.1.0
 */
class responseMock {

	public $apiKey;
	public $ipAddress;

	public function __construct($apiKey, $ipAddress) {
		$this->apiKey = $apiKey;
		$this->ipAddress = $ipAddress;
	}

	public function getRawResponse() {
	}
}