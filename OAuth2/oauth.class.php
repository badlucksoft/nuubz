<?php
/*
The MIT License (MIT)

Copyright (c) 2016 Raymond Rodgers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/**
	\mainpage
	These classes implement the OAuth2 specification in RFC 6749 (https://tools.ietf.org/html/rfc6749 ) for Access Token support to OAuth2
	servers. Though you can modify the OAuthBase class for specific hosts, I have had success
	communicating with remote OAuth2 servers by creating subclasses for them, such as with Google
	and Facebook.
	
	NOTE
	
	This is a work in progress and currently has many unused and redundant variables that will be pared
	down as work proceeds.
	
	Information about the Nuubz project and its development progress can be found at http://www.badlucksoft.com and http://www.nuubz.com .
*/

/**
	\file
	\brief Contains class OAuthBase
	\class OAuthBase
	\brief OAuth2 base class
	
	This class does most of the heavy lifting for OAuth2 communications; to communicate with a
	service that does not already have an implementation, create a subclass of OAuthBase as the
	starting point.
	
	\todo Everything.
*/
abstract class OAuthBase
{
	const AUTH_BASIC = 0x00000001;
	const AUTH_POST_FORM_ENCODED = 0x00000002;
	const AUTH_CLIENT_ID_IN_HEADER = 0x00000004;
	const AUTH_BEARER = 0x00000008;
	
	protected $serviceName, $tokenEndpoint, $authorizeEndpoint,$authorizeRedirectURI, $authStateValue, $authServerURL, $resourceServerURL, $accessToken, $accessTokenExpiry,$refreshToken, $authorizationCode,
			$client_id,$client_secret,$resourceScopes,$scopeSeparator,$state,$redirectURI, $useSSLTLS, $clientAuthentication,
			$user_id,$user_first_name, $user_last_name, $user_email, $transmissionHeaders;
	function __construct()
	{
		$this->serviceName = null;
		$this->authServerURL = null;
		$this->resourceServerURL = null;
		$this->accessToken = null;
		$this->refreshToken = null;
		$this->authGrant = null;
		$this->client_id = null;
		$this->client_secret = null;
		$this->tokenEndpoint = null;
		$this->authorizeEndpoint = null;
		$this->useSSLTLS = true;
		$this->resourceScopes = array();
		$this->scopeSeparator = ' ';
		$this->user_id = null;
		$this->user_first_name = null;
		$this->user_last_ame = null;
		$this->user_email = null;
		$this->transmissionHeaders = array();
	}
	/**
		\brief Turn SSL/TLS usage on or off.
		
		This function sets the internal variable that controls whether SSL/TLS is used when
		communicating with the service provider. Usually, this will need to be set to true,
		which is its default value.
	*/
	protected function setSSLTLS($USE)
	{
		$old = $this->useSSLTLS;
		$this->useSSLTLS = $USE;
		return $old;
	}
	/**
		\brief Returns the current status of whether service is configured to use SSL/TLS.
	*/
	function getSSLTLS()
	{
		return $this->useSSLTLS;
	}
	/**
		\brief Sets the service provider specific client identifier.
		
		\param $CLIENT_ID Service provided identifier string.
		
		This function sets the OAuth2 service provider's client identifier for your site.
	*/
	function setClientID($CLIENT_ID)
	{
		$oldCID = $this->client_id;
		$this->client_id = $CLIENT_ID;
		return $oldCID;
	}
	function getClientID()
	{
		return $this->client_id;
	}
	/**
		\brief Sets service provider specific client secret value.
		
		\param $CLIENT_SECRET Secret identifier value provided by service provider.
		
		This function sets the service provider's secret identifier value that is used to confirm
		authenticity of your communications.
	*/
	function setClientSecret($CLIENT_SECRET)
	{
		$oldSecret = $this->client_secret;
		$this->client_secret = $CLIENT_SECRET;
		return $oldSecret;
	}
	function getClientSecret()
	{
		return $this->client_secret;
	}
	function setAuthFlag($FLAG)
	{
		$old = $this->checkAuthFlag($FLAG);
		$this->clientAuthentication |= $FLAG;
		return $old;
	}
	function checkAuthFlag($FLAG)
	{
		$set = false;
		if( ($this->clientAuthentication & $FLAG) == $FLAG) $set = true;
		return $set;
	}
	function clearAuthFlag($FLAG)
	{
		$old = $this->checkAuthFlag($FLAG);
		$this->clientAuthentication ^= $FLAG;
		return $old;
	}
	function BasicAuth()
	{
		$auth = false;
		if( ! empty($this->client_id) && ! empty($this->client_secret) ) $auth = base64_encode($this->client_id . ':' . $this->client_secret);
		return $auth;
	}
	protected function setServiceName($NAME)
	{
		$oldName = $this->serviceName;
		$this->serviceName = $NAME;
		return $oldName;
	}
	function getServiceName()
	{
		return $this->serviceName;
	}
	/**
		\brief Sets the token endpoint for the service provider.
		
		This function sets the token endpoint for the provider; this endpoint provides the token
		that is used to retrieve the user data as part of the protocol. This function should
		not normally be called or used by the website functionality directly; a service specific
		subclass should call this function as part of their constructor. (Thus the function is
		protected instead of public.)
	*/
	protected function setTokenEndpoint($URL)
	{
		$oldURL = $this->tokenEndpoint;
		$this->tokenEndpoint = $URL;
		return $oldURL;
	}
	function getTokenEndpoint()
	{
		return $this->tokenEndpoint;
	}
	/**
		\brief Sets the service authorization endpoint. 
		
		This function sets the service specific authorization endpoint which is the first step
		in the OAuth2 process; this is the URL to which the user's web client is redirected as
		part of the authentication/authorization process.  This function should
		not normally be called or used by the website functionality directly; a service specific
		subclass should call this function as part of their constructor. (Thus the function is
		protected instead of public.)
	*/
	protected function setAuthorizeEndpoint($URL)
	{
		$old = $this->authorizeEndpoint;
		$this->authorizeEndpoint = $URL;
		return $old;
	}
	function getAuthorizeEndpoint()
	{
		return $this->authorizeEndpoint;
	}
	function setAuthorizeRedirectURI($URL)
	{
		$old = $this->authorizeRedirectURI;
		$this->authorizeRedirectURI = $URL;
		return $old;
	}
	function getAuthorizeRedirectURI()
	{
		return $this->authorizeRedirectURI;
	}
	protected function setAuthServerURL($URL)
	{
		$oldURL = $this->authServerURL;
		$this->authServerURL = $URL;
		return $oldURL;
	}
	function getAuthServerURL()
	{
		return $this->authServerURL;
	}
	protected function setResourceServerURL($URL)
	{
		$oldURL = $this->resourceServerURL;
		$this->resourceServerURL = $URL;
		return $oldURL;
	}
	function getResourceServerURL()
	{
		return $this->resourceServerURL;
	}
	protected function setAccessToken($TOKEN)
	{
		$old = $this->accessToken;
		$this->accessToken = $TOKEN;
		return $old;
	}
	function getAccessToken()
	{
		return $this->accessToken;
	}
	protected function setRefreshToken($TOKEN)
	{
		$old = $this->refreshToken;
		$this->refreshToken = $TOKEN;
		return $old;
	}
	function getRefreshToken()
	{
		return $this->refreshToken;
	}
	protected function setAccessTokenExpiry($TIME)
	{
		$old = $this->accessTokenExpiry;
		$this->accessTokenExpiry = $TIME;
		return $old;
	}
	function getAccessTokenExpiration()
	{
		return $this->accessTokenExpiry;
	}
	function isAccessTokenExpired()
	{
		$expired = true;
		if( ! empty($this->accessTokenExpiry) )
		{
			if( time() <= strtotime($this->accessTokenExpiry) ) $expired = false;
		}
		else $expired =false; // assume the token is valid if we have no expiry.
		return true;
	}
	/**
		\brief Compares the authorization state value received to the one already set.
	*/
	function verifyAuthorizationState($STATE)
	{
		$matches = false;
		if( strcmp($this->authStateValue,$STATE) == 0 ) $matches = true;
		return $matches;
	}
	function setAuthorizationCode($CODE) // also known as authorization grant
	{
		$old = $this->authorizationCode;
		$this->authorizationCode = $CODE;
		return $old;
	}
	function getAuthorizationCode()
	{
		return $this->authorizationCode;
	}
	function hasScopesSpecified()
	{
		$hasScopes = false;
		if( isset($this->resourceScopes) && is_array($this->resourceScopes) && count($this->resourceScopes) > 0 ) $hasScopes = true;
		return $hasScopes;
	}
	/**
		\brief Adds a resource scope.
		
		\param $SCOPE Service specific resource scope string.
		
		This function adds the passed in resource scope string to an internal array that is passed
		to the remote service provider. The string is only added if it does not already exist in the
		array. The resource scope(s) is(are) the user data you wish to receive from the service provider.
		
		\return int The number of scopes currently set for requests.
	*/
	function addResourceScope($SCOPE)
	{
		if( ! in_array($SCOPE,$this->resourceScopes) ) $this->resourceScopes[] = $SCOPE;
		return count($this->resourceScopes);
	}
	function getResourceScopes()
	{
		return $this->resourceScopes;
	}
	function authRedirectResourceOwner()
	{
		$params = array();
		$params['client_id'] = urlencode($this->getClientID());
		$params['response_type'] = 'code';
		if(function_exists('openssl_random_pseudo_bytes') ) $this->authStateValue = sha1(openssl_random_pseudo_bytes(1024));
		else $this->authStateValue = OAuthBase::generateCode();
		$params['state'] = $this->authStateValue;
		if( ! is_null($this->getAuthorizeRedirectURI()) ) $params['redirect_uri'] = urlencode('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI());
		if( $this->hasScopesSpecified() )
		{
			$scopes = $this->getResourceScopes();
			$params['scope'] = implode($this->scopeSeparator,$scopes);
		}
		$output = array();
		foreach($params as $key => $value)
			$output[] = $key . '=' . urlencode($value);
		unset($params);
		return $this->authorizeEndpoint . '?' . implode('&',$output);
	}
	function getUserAgentString()
	{
		return 'Nuubz OAuth (' . $this->getServiceName() . ')';
	}
	function addHeader($HEADER,$CONTENT)
	{
		if( is_null($this->transmissionHeaders) ) $this->transmissionHeaders = array();
		$this->transmissionHeaders[$HEADER] = $CONTENT;
	}
	function removeHeader($HEADER)
	{
		if( isset($this->transmissionHeaders[$HEADER]) && ! empty($this->transmissionHeaders[$HEADER])) unset($this->transmissionHeaders[$HEADER]);
	}
	function authenticate()
	{
		$c = curl_init('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getTokenEndpoint());
		curl_setopt($c,CURLOPT_USERAGENT,$this->getUserAgentString());
		curl_setopt($c,CURLOPT_POST,true);
		if( $this->getSSLTLS() )
		{
			curl_setopt($c,CURLOPT_SSL_VERSION,CURL_SSLVERSION_TLSv1_2);
			curl_setopt($c,CURLOPT_SSL_VERIFYHOST,2);
			if(version_compare(PHP_VERSION,'7.0.7','>=')) curl_setopt($c,CURL_SSL_VERIFYSTATUS,true);
		}
		curl_setopt($c,CURLOPT_RETURNTRANSFER,true);
		$headers = array();
		$vars = array(
			'grant_type' => 'authorization_code',
			'redirect_uri' => 'http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI()
			);
		if( ! empty($this->refreshToken) && $this->isAccessTokenExpired())
		{
			$vars['refresh_token'] = $this->refreshToken;
			$vars['grant_type'] = 'refresh_token';
		}
		else
		{
			$vars['code'] = $this->getAuthorizationCode();

		}
		if( ! empty($this->transmissionHeaders) && count($this->transmissionHeaders) > 0)
		{
			foreach($this->transmissionHeaders as $h => $v)
			{
				if( ! empty($h) && ! empty($v) ) $headers[] = $h . ': ' . $v;
			}
		}
		if( $this->checkAuthFlag(OAuthBase::AUTH_CLIENT_ID_IN_HEADER) && ! is_null($this->getClientID()) && ! isset($this->transmissionHeaders['Client-ID'])) 
		{
			$headers[] = 'Client-ID: ' . $this->getClientID();
		}
		if( $this->checkAuthFlag(OAuthBase::AUTH_BASIC) && ! is_null($this->getClientID()) && ! is_null($this->getClientSecret()))
		{
			$headers[] = 'Authorization: Basic ' . $this->BasicAuth();
			//echo 'Authorization: Basic ' . $this->BasicAuth() . '<br>';
		}
		else
		{
			if(! is_null($this->getClientID()) && ! is_null($this->getClientSecret()))
			{
				$vars['client_id'] =  $this->getClientID();
				$vars['client_secret'] = $this->getClientSecret();
				
			}
		}
		if( ! empty($headers) ) curl_setopt($c,CURLOPT_HTTPHEADER,$headers);
		if( $this->checkAuthFlag(OAuthBase::AUTH_POST_FORM_ENCODED) )
		{
			$pVars = array();
			foreach($vars as $name => $value)
				$pVars[] = $name . '=' . urlencode($value);
			curl_setopt($c,CURLOPT_POSTFIELDS,implode('&',$pVars));
			unset($pVars);
		}
		else
			curl_setopt($c,CURLOPT_POSTFIELDS,$vars);
		curl_setopt($c,CURLOPT_HEADER,true);
		$result = curl_exec($c);
		if( $result === false)
		{
			$ce = curl_errno($c);
			throw new OAuthCURLException("OAuthClass: A CURL error has occurred: " . curl_error($c), $ce);
		}
		$headerSize = curl_getinfo($c,CURLINFO_HEADER_SIZE);
		$httpResponseCode = curl_getinfo($c,CURLINFO_HTTP_CODE);
		$headerText = substr($result,0,$headerSize);
		$result = substr($result,$headerSize);
		$headers = explode("\n",$headerText);
		unset($headerText);
		$contentType = OAuthBase::getHeaderValue('Content-Type',$headers);
		if( strpos($contentType,';') !== false) $contentType = substr($contentType,0,strpos($contentType,';'));

		/*
		may need to get received headers and process them for other data, including the access token as it's sometimes returned that way
		*/
		curl_close($c);
		if( 200 == $httpResponseCode ) $this->processAuthGrant($result,$contentType);
		elseif( 400 <= $httpResponseCode && 500 > $httpResponseCode)
		{
			if( strcasecmp($contentType,'application/json') == 0 )
			{
				$error = json_decode($result);
				if( isset($error->error) )
				{
					if( strcasecmp($error->error,'invalid_grant') == 0) throw new OAuthInvalidGrantException(isset($error->error_description) ? $error->error_description:null);
					if( strcasecmp($error->error,'invalid_client') == 0)
					{
						$msg = array();
						if( isset($error->error_description) ) $msg[] = $error->error_description;
						if( 401 == $httpResponseCode )
						{
							$authScheme = OAuthBase::getHeaderValue('WWW-Authenticate',$headers);
							if( ! empty($authScheme) ) $msg[] = 'Server suggests using ' . $authScheme . ' authentication.';
						}
						if( isset($error->error_uri) ) $msg[] = 'Explanation at ' . $error->error_uri;
						throw new OAuthInvalidClientException( empty($msg) ? null:implode('; ',$msg));
						
					}
					throw new OAuthException(isset($error->error_description) ? $error->error_description:$error->error);
				}
			}
			else
			{
				echo $contentType;
				print_r($result);
			}
		}
		else print_r($result);
		return $result;
	}
	static function generateCode($LENGTH = 32)
	{
		$pool = str_split('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._',1);
		$code = '';
		$randFunc = 'mt_rand';
		$poolSize = count($pool);
		if(version_compare(PHP_VERSION,'7.0.0', '>=') ) $randFunc = 'random_int';
		for( $i = 0; $i < $LENGTH; $i++)
		{
			shuffle($pool);
			$code .= $pool[$randFunc(0,$poolSize-1)];
		}
		return $code;
	}
	static function getHeaderValue($NEEDLE,$HAYSTACK)
	{
		$value = null;
		if( ! empty($NEEDLE) && ! empty($HAYSTACK) && is_array($HAYSTACK) )
		{
			foreach( $HAYSTACK as $header)
			{
				$header = trim($header);
				if( ! empty($header) && strlen($header) > 0)
				{
					if( preg_match('/^' . preg_quote($NEEDLE) . ':\s+(.*)$/i',$header,$content) > 0 )
					{
						$value = $content[1];
					}
				}
			}
		}
		return $value;
	}
	function __sleep()
	{
		return array('serviceName', 
			'tokenEndpoint',
			'authorizeEndpoint',
			'authorizeRedirectURI',
			'authStateValue',
			'authServerURL',
			'resourceServerURL',
			'accessToken',
			'accessTokenExpiry',
			'refreshToken',
			'authorizationCode',
			'client_id',
			'client_secret',
			'resourceScopes',
			'scopeSeparator',
			'state',
			'redirectURI',
			'useSSLTLS',
			'clientAuthentication');
	}
	function __wakeup()
	{
	}
	/*
	function __debuginfo()
	{
		return array(
				'serviceName' => $this->serviceName,
				'authServerURL' => $this->authServerURL,
				'resourceServerURL' => $this->resourceServerURL,
				'client_id' => $this->client_id,
				'SSL/TLS' => ($this->getSSLTLS() ? 'Yes':'No'),
				'accessTokenExpiry' => $this->accessTokenExpiry
			);
	}
	*/
	/**
		\brief Process authorization grant
		
		Process the received authorization grant type. As some authorization grants are done in XML and others in JSON
		the MIME type received from the server is passed along.
		
		\param $GRANT A string containing the authorization grant data.
		\param $TYPE MIME type of the received data.
	*/
	abstract protected function processAuthGrant($GRANT,$TYPE);
	/**
		\brief Process resource response
		
		Process the resource response received by the server. This is to be handled in subclasses only, as it service specific.
	*/
	abstract protected function processResource($RESOURCE);
}

/**
	\class OAuthException
	\brief Base class for general and specific OAuth exceptions.
	
	The OAuthException base class acts as both a general exception that may be thrown by this system
	as well as a catch-all for all subclasses. This will allow you to distinguish between various
	OAuth exceptions and exceptions from other errors.
*/
class OAuthException extends Exception
{
	function __construct($MESSAGE = 'An OAuth exception occurred', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthCURLExcepiton extends OAuthException
{
	function __construct($MESSAGE = 'An error within CURL occurred', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthInvalidGrantException
	\brief Invalid Grant Exception
	
	The authorization grant sent to the remote service was considered invalid. It's possible the refresh
	token (if provided or available) may need to be submitted to obtain a new authorization grant.
*/
class OAuthInvalidGrantException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid grant', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthInvalidRequestException
	\brief Invalid Request Exception
*/
class OAuthInvalidRequestException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid request', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthInvalidClientException
	\brief Invalid Client Exception
	
	This exception is thrown when client authentication fails. This failure may be for a range of reasons
	including the client is unknown, the authentication is missing, or the authentication method is unsupported.
*/
class OAuthInvalidClientException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid client', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthUnauthorizedClientException
	\brief Unauthorized Client Exception
	
	The authenticated client isn't authorized to use the attempted authorization
	grant type.
*/
class OAuthUnauthorizedClientException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; unauthorized client', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthUnsupportedGrantTypeException
	\brief Unsupported Grant Type
	
	The authorization server doesn't support the requested grant type. 
*/
class OAuthUnsupportedGrantTypeException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; unsupported grant type', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
/**
	\class OAuthInvalidScopeException
	\brief Invalid Scope Exception
	
	The requested scope or scopes is/are invalid, malformed, or unrecognized.
*/
class OAuthInvalidScopeException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid scope', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
