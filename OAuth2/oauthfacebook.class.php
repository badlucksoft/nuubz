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
require_once 'oauth.class.php';

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
		$this->setAuthorizeRedirectURI('yourdomainhere/oauthresponse');
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
					if( ! is_null($this->getAccessToken()) ) echo 'successfully obtained access token!';
				}
				catch(Exception $e)
				{
				}
			}
		}
		$vars = array('client_id' => urlencode($this->getClientID()), 'client_secret' => urlencode($this->getClientSecret()),'redirect_uri' => urlencode('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI()),'code' => null);
		
	}
	protected function processResource($RESOURCE)
	{
	}
}