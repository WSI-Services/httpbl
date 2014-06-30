Build Status: [![Build Status](https://travis-ci.org/WSI-Services/httpbl.svg?branch=master)](https://travis-ci.org/WSI-Services/httpbl)

###Table of Contents
* [WSI-Services httpBL](#wsiserviceshttpbl)
* [About Project Honey Pot](#aboutprojecthoneypot)
    * [HTTP Blacklist](#httpblacklist)
* [Installing WSI-Services httpBL](#installingwsiserviceshttpbl)
    * [GIT](#git)
    * [Composer](#composer)
* [Using httpBL](#usinghttpbl)
    * [Namespace](#namespace)
    * [Class: httpBL](#classhttpbl)
    * [Class: response](#classresponse)
* [Utilities](#utilities)
    * [phpDocumentor](#phpdocumentor)
    * [phpUnit](#phpunit)
        * [Code Coverage](#codecoverage)

WSI-Services httpBL
====
PHP library for checking IPv4 addresses against Project Honey Pots Blacklist.
An API key from Project Honey Pot is required to utilize this library.  You can
create an account and obtain an API key by [creating an
account](http://www.projecthoneypot.org/create_account.php) at [Project Honey
Pot](http://www.projecthoneypot.org), then [request an access
key](http://www.projecthoneypot.org/httpbl_configure.php).

About Project Honey Pot
====
<img style="float:right; border: 1px solid #d7d7d7; padding: 4px;" src="http://www.projecthoneypot.org/images/target.gif" alt="Project Honey Pot">
Project Honey Pot is the first and only distributed system for identifying
spammers and the spambots they use to scrape addresses from your website. Using
the Project Honey Pot system, you can install addresses that are custom-tagged
to the time and IP address of a visitor to your site. If one of these addresses
begins receiving email, not only can they tell that the messages are spam, but
also the exact moment when the address was harvested and the IP address that
gathered it.

HTTP Blacklist
----
The HTTP Blacklist, or "http:BL", is a system that allows website administrators
to take advantage of the data generated by Project Honey Pot in order to keep
suspicious and malicious web robots off their sites. Project Honey Pot tracks
harvesters, comment spammers, and other suspicious visitors to websites. Http:BL
makes this data available to any member of Project Honey Pot in an easy and
efficient way.

Http:BL provides data back about the IP addresses of visitors to your website.
Data is exchanged over DNS. You may query your local DNS server and receive a
response back that indicates the type of visitor to your site, how threatening
that visitor is, and how long it's been since the visitor has last been seen
within the Project Honey Pot trap network.

Installing WSI-Services httpBL
====

GIT
----
Clone the GIT repository locally:

```shell
$ git clone https://github.com/WSI-Services/httpbl.git
```

Composer
----
Add the required sections to your `composer.json` file:

```json
"require": {
	"wsiservices/httpbl": "dev-master"
},
"repositories": [
	{
		"type": "git",
		"url": "https://github.com/WSI-Services/httpbl.git"
	}
]
```

Using httpBL
====

Namespace
----

```php
use WSIServices\httpBL;
```

Class: httpBL
----

```php
$httpBlacklist = new httpBL\httpBL($apiKey);
$response = $httpBlacklist->lookup($ipAddress);
```

Class: response
----

```php
if($response->inBlacklist()) {
	echo 'Response Time-To-Live: '
		.$response->getTtl().PHP_EOL;

	$responseType = $reponse->getType();

	echo 'Visitor Type Id      : '
		.$responseType.PHP_EOL;
	echo 'Visitor Type         : '
		.$response->getTypeName($responseType).PHP_EOL;

	if($responseType === httpBL\response::VISITOR_SEARCH_ENGINE) {
		$searchEngineId = $response->getSearchEngine();

		echo 'Search Engine Id     : '
			.$searchEngineId.PHP_EOL;
		echo 'Search Engine        : '
			.$response->getSearchEngineName($searchEngineId).PHP_EOL;
	} else {
		echo 'Threat Score         : '
			.$response->getThreatScore().PHP_EOL;
		echo 'Last Active          : '
			.$response->getLastActive().PHP_EOL;
	}
} else {
	echo 'Visitor ('.$response->getIpAddress()
		.') is not in the blacklist.'.PHP_EOL;
}
```

Utilities
====
This library includes utilities for documentation and testing.

phpDocumentor
----
From the root of the project, run the following command:

```shell
$ ./utilities/phpdocumentor.sh
```

**Example Output:**

```shell
Collecting files .. OK
Initializing parser .. OK
Parsing files
Parsing /path/to/httpBL/source/httpBL.php
Parsing /path/to/httpBL/source/response.php
Storing cache in "/path/to/httpBL/documentation/api" .. OK
Load cache                                                         ..    0.014s
Preparing template "responsive"                                    ..    0.367s
Preparing 13 transformations                                       ..    0.000s
Build "elements" index                                             ..    0.003s
Replace textual FQCNs with object aliases                          ..    0.038s
Build "packages" index                                             ..    0.025s
Collect all markers embedded in tags                               ..    0.007s
Build "namespaces" index and add namespaces to "elements"          ..    0.002s
Transform analyzed project into artifacts                          ..    1.225s
Analyze results and write report to log                            ..    0.006s
```

The documentation for this library is generated in the `documentation/api`
directory.

phpUnit
----
From the root of the project, run the following command:

```shell
$ ./utilities/phpunit.sh
```

**Example Output:**

```shell
PHPUnit 4.0.15 by Sebastian Bergmann.

Configuration read from /path/to/httpBL/phpunit.xml

.........................................................

Time: 4.58 seconds, Memory: 4.75Mb

OK (57 tests, 154 assertions)

Generating code coverage report in Clover XML format ... done

Generating code coverage report in HTML format ... done


Code Coverage Report:
  2014-04-19 20:04:24

 Summary:
  Classes: 100.00% (2/2)
  Methods: 100.00% (18/18)
  Lines:   100.00% (106/106)

\WSIServices\httpBL::httpBL
  Methods: 100.00% ( 5/ 5)   Lines: 100.00% ( 13/ 13)
\WSIServices\httpBL::response
  Methods: 100.00% (13/13)   Lines: 100.00% ( 93/ 93)
```

If you would like to perform live tests with your Project Honey Pot API key,
edit file `test\httpBLLookupLiveTest.php` and locate the following line.

```php
define('WSIServices\httpBL\PROJECT_HONEYPOT_API_KEY', 'abcdefghijkl');
```

Replace `abcdefghijkl` with the API key provided to you by Project Honey Pot.

### Code Coverage
Running phpUnit generates logs in directory `test/log`.  Below you can see the
files and discriptions of the generated output.

<dl>
	<dt>coverage.xml</dt>
	<dd>The XML format for code coverage information logging produced by PHPUnit, loosely based upon the one used by <a href="http://www.atlassian.com/software/clover/">Clover</a>.</dd>
	<dt>report (directory)</dt>
	<dd>The HTML format for code coverage information; provides a package overview, namespace &amp; class discriptions, charts, and reports (including errors, markers, and depricated elements).</dd>
	<dt>testdox.txt</dt>
	<dd>The text format of the PHPUnit TestDox, to generate agile project documentation based on the tests.</dd>
	<dt>testdox.html</dt>
	<dd>The HTML format of the PHPUnit TestDox, to generate agile project documentation based on the tests.</dd>
	<dt>logfile.tap</dt>
	<dd>The Test Anything Protocol (TAP) is Perl's simple text-based interface between testing modules.</dd>
	<dt>logfile.json</dt>
	<dd>The <a href="http://www.json.org/">JavaScript Object Notation (JSON)</a> is a lightweight data-interchange format.</dd>
</dl>

You can find more out about phpUnit logging in their documentation
[Chapter 14. Logging](http://phpunit.de/manual/4.0/en/logging.html) and
[Chapter 15. Other Uses for Tests](http://phpunit.de/manual/4.0/en/other-uses-for-tests.html).