<?php
/*
	RFC 6749
	Important sections:
		4.1
		4.2.1 Authorization Request
		4.2.2 Access Token Response
*/
abstract class OAuthBase
{
	const AUTH_BASIC = 0x00000001;
	const AUTH_POST_FORM_ENCODED = 0x00000002;
	
	protected $serviceName, $tokenEndpoint, $authorizeEndpoint,$authorizeRedirectURI, $authStateValue, $authServerURL, $resourceServerURL, $accessToken, $accessTokenExpiry,$refreshToken, $authorizationCode,
			$client_id,$client_secret,$resourceScopes,$scopeSeparator,$state,$redirectURI, $useSSLTLS, $clientAuthentication,
			$user_id,$user_first_name, $user_last_name, $user_email;
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
		$this->user_last_name = null;
		$this->user_email = null;
	}
	protected function setSSLTLS($USE)
	{
		$old = $this->useSSLTLS;
		$this->useSSLTLS = $USE;
		return $old;
	}
	function getSSLTLS()
	{
		return $this->useSSLTLS;
	}
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
	protected function setAuthorizeRedirectURI($URL)
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
		$this->authStateValue = OAuthBase::generateCode();
		$params['state'] = urlencode($this->authStateValue);
		if( ! is_null($this->getAuthorizeRedirectURI()) ) $params['redirect_uri'] = urlencode('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI());
		if( $this->hasScopesSpecified() )
		{
			$scopes = $this->getResourceScopes();
			$params['scope'] = urlencode(implode($this->scopeSeparator,$scopes));
		}
		$output = array();
		foreach($params as $key => $value)
			$output[] = $key . '=' . $value;
		//echo $this->authorizeEndpoint . '?' . implode('&',$output) . "\n";
//		unset($output);
		unset($params);
		return $this->authorizeEndpoint . '?' . implode('&',$output);
	}
	function getUserAgentString()
	{
		return 'Nuubz OAuth (' . $this->getServiceName() . ')';
	}
	function authenticate()
	{
		$c = curl_init('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getTokenEndpoint());
		curl_setopt($c,CURLOPT_USERAGENT,$this->getUserAgentString());
		curl_setopt($c,CURLOPT_POST,true);
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
		//preout($vars);
		if( ! empty($headers) ) curl_setopt($c,CURLOPT_HTTPHEADER,$headers);
		if( $this->checkAuthFlag(OAuthBase::AUTH_POST_FORM_ENCODED) )
		{
			$pVars = array();
			foreach($vars as $name => $value)
				$pVars[] = $name . '=' . urlencode($value);
			curl_setopt($c,CURLOPT_POSTFIELDS,implode('&',$pVars));
			//echo 'post field set to ' . implode('&',$pVars) . '<br>'; 
			unset($pVars);
		}
		else
			curl_setopt($c,CURLOPT_POSTFIELDS,$vars);
		curl_setopt($c,CURLOPT_HEADER,true);
		$result = curl_exec($c);
		$headerSize = curl_getinfo($c,CURLINFO_HEADER_SIZE);
		$httpResponseCode = curl_getinfo($c,CURLINFO_HTTP_CODE);
		$headerText = substr($result,0,$headerSize);
		$result = substr($result,$headerSize);
//		echo $headerText . "\n";
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
				preout($result);
			}
		}else preout($result);
		return $result;
	}
	static function generateCode()
	{
		$pool = str_split('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._',1);
		$code = '';
		$randFunc = 'mt_rand';
		$poolSize = count($pool);
		if(version_compare(PHP_VERSION,'7.0.0', '>=') ) $randFunc = 'random_int';
		for( $i = 0; $i < 32; $i++)
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
	abstract protected function processAuthGrant($GRANT,$TYPE);
	abstract protected function processResource($RESOURCE);
}

class OAuthGoogle extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Google');
		parent::setAuthorizeEndpoint('accounts.google.com/o/oauth2/v2/auth');
		parent::setTokenEndpoint('www.googleapis.com/oauth2/v4/token');
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.email');
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.profile');
		$this->setAuthorizeRedirectURI('dev.nuubz.com/oauthresponse');
		$this->setAuthFlag(OAuthBase::AUTH_BASIC);
		$this->setAuthFlag(OAuthBase::AUTH_POST_FORM_ENCODED);
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
		//preout($TYPE);
		//preout($GRANT);
		if( ! empty($GRANT) )
		{
			if( strcasecmp($TYPE,'application/json') == 0 )
			{
				try
				{
				$tokenData = json_decode($GRANT,true);
				if( isset($tokenData['access_token']) ) $this->setAccessToken($tokenData['access_token']);
				if( isset($tokenData['refresh_token']) ) $this->setRefreshToken($tokenData['refresh_token']);
				if( isset($tokenData['expires_in']) ) $this->setAccessTokenExpiry(date('Y-m-d H:i:s',strtotime('+' . $tokenData['expires_in'] . ' seconds')));
				//var_dump($tokenData);
				if( ! is_null($this->getAccessToken()) ) echo 'successfully obtained access token!';
				}
				catch(Exception $e)
				{
					//echo $e->getMessage(). "\n";
				}
				//exit();
			}
		}
	}
	protected function processResource($RESOURCE)
	{
	}
}

class OAuthClef extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Clef');
		parent::setAuthServerURL('clef.io/api/v1/authorize');
		parent::setResourceServerURL('clef.io/api/v1/info');
	}
	function processAuthGrant($GRANT,$TYPE)
	{
	}
	function processResource($RESOURCE)
	{
	}
}

class OAuthPatreon extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Patreon');
		parent::setAuthorizeEndpoint('www.patreon.com/oauth2/authorize');
		parent::setTokenEndpoint('api.patreon.com/oauth2/token');
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
	}
	protected function processResource($RESOURCE)
	{
	}
}

class OAuthDisqus extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Disqus');
		parent::setAuthorizeEndpoint('disqus.com/api/oauth/2.0/authorize/');
		parent::setTokenEndpoint('disqus.com/api/oauth/2.0/access_token/');
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
	}
	protected function processResource($RESOURCE)
	{
	}
}

class OAuthFacebook extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Facebook');
		parent::setAuthorizeEndpoint('www.facebook.com/dialog/oauth');
		parent::setTokenEndpoint('graph.facebook.com/v2.3/oauth/access_token');
		parent::setResourceServerURL('somethingelseatfacebook');
		$this->scopeSeparator = ',';
		$this->addResourceScope('email');
		$this->addResourceScope('public_profile');
		$this->setAuthorizeRedirectURI('dev.nuubz.com/oauthresponse');
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
		if( strpos($TYPE,';') !== false) $TYPE = substr($TYPE,0,strpos($TYPE,';'));
		if( ! empty($GRANT) )
		{
			if( strcasecmp($TYPE,'application/json') == 0 )
			{
				try
				{
				$tokenData = json_decode($GRANT,true);
				if( isset($tokenData['access_token']) ) $this->setAccessToken($tokenData['access_token']);
				if( isset($tokenData['refresh_token']) ) $this->setRefreshToken($tokenData['refresh_token']);
				if( isset($tokenData['expires_in']) ) $this->setAccessTokenExpiry(date('Y-m-d H:i:s',strtotime('+' . $tokenData['expires_in'] . ' seconds')));
				//preout($tokenData);
				if( ! is_null($this->getAccessToken()) ) echo 'successfully obtained access token!';
				}
				catch(Exception $e)
				{
					//echo $e->getMessage(). "\n";
				}
				//exit();
			}
		}
		$vars = array('client_id' => urlencode($this->getClientID()), 'client_secret' => urlencode($this->getClientSecret()),'redirect_uri' => urlencode('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI()),'code' => null);
		
	}
	protected function processResource($RESOURCE)
	{
	}
}

class OAuthTest extends OAuthBase
{
	function __construct($AUTHCODE = null, $REFRESH_TOKEN = null)
	{
		parent::__construct();
		/*
			Info for use with the test OAuth daemon installed on Aragorn's Fedora dev server and at oauthdev.nuubz.com
			https://github.com/oauth-io/oauthd
		*/
		if( ! empty($AUTHCODE) ) $this->setAuthorizationCode($AUTHCODE);
		$this->setServiceName('Test');
		$this->setTokenEndpoint('localhost/oauth2/token.php');
		$this->setAuthorizeEndpoint('localhost/oauth2/authorize.php');
		$this->setAuthorizeRedirectURI('localhost/oauth2/postauth.php');
		//$this->setResourceServerURL('term.ie/oauth/example/access_token.php');
		$this->addResourceScope('first_name');
		$this->addResourceScope('last_name');
		$this->addResourceScope('username');
		$this->setSSLTLS(false);
		$this->setClientID('testclient');
		$this->setClientSecret('testpass');
		if( ! empty($REFRESH_TOKEN) )
		{
			$this->setRefreshToken($REFRESH_TOKEN);
			$this->authenticate();
		}
		//$tokenData = $this->authenticate();
	//	print_r($tokenData);
	}
	function getResource()
	{
		if( $this->getAccessTokenExpired()) $this->authenticate();
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
		echo "\t===\tprocessAuthGrant\t===\n";
		if( ! empty($GRANT) )
		{
			if( strcasecmp($TYPE,'application/json') == 0 )
			{
				try
				{
				$tokenData = json_decode($GRANT,true);
				if( isset($tokenData['access_token']) ) $this->setAccessToken($tokenData['access_token']);
				if( isset($tokenData['refresh_token']) ) $this->setRefreshToken($tokenData['refresh_token']);
				if( isset($tokenData['expires_in']) ) $this->setAccessTokenExpiry(date('Y-m-d H:i:s',strtotime('+' . $tokenData['expires_in'] . ' seconds')));
				var_dump($tokenData);
				}
				catch(Exception $e)
				{
					echo $e->getMessage(). "\n";
				}
				//exit();
			}
		}
	}
	protected function processResource($RESOURCE)
	{
	}
}
class OAuthException extends Exception
{
	function __construct($MESSAGE = 'An OAuth exception occurred', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthInvalidGrantException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid grant', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthInvalidRequestException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid request', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthInvalidClientException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid client', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthUnauthorizedClientException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; unauthorized client', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthUnsupportedGrantTypeException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; unsupported grant type', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
class OAuthInvalidScopeException extends OAuthException
{
	function __construct($MESSAGE = 'OAuth exception; invalid scope', $CODE = 0, $PREVIOUS = null)
	{
		parent::__construct($MESSAGE,$CODE,$PREVIOUS);
	}
}
