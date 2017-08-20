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

/**
	\file
	\brief Contains class OAuthGoogle
	
	\class OAuthGoogle
	\brief Google subclass
	
	This is the subclass that will handle Google OAuth2 communications.
	
	\todo Everything.
*/

class OAuthGoogle extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Google');
		$c = curl_init('https://accounts.google.com/.well-known/openid-configuration');
		curl_setopt($c,CURLOPT_USERAGENT,$this->getUserAgentString());
		curl_setopt($c,CURLOPT_RETURNTRANSFER,true);
		$discoveryDoc = curl_exec($c);
		$disc = json_decode($discoveryDoc,true);
		curl_close($c);
		unset($discoveryDoc);
		parent::setAuthorizeEndpoint($disc['authorization_endpoint']);
		parent::setTokenEndpoint($disc['token_endpoint']);
		parent::setUserInfoEndpoint($disc['userinfo_endpoint']);
		parent::setRevocationEndpoint($disc['revocation_endpoint']);
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.email');
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.profile');
		$this->setSSLTLS(true);
		$this->setAuthFlag(OAuthBase::AUTH_BASIC);
		$this->setAuthFlag(OAuthBase::AUTH_POST_FORM_ENCODED);
	}
	protected function processAuthGrant($GRANT,$TYPE)
	{
		if( ! empty($GRANT) )
		{
			if( strcasecmp($TYPE,'application/json') == 0 )
			{
				try
				{
					$tokenData = json_decode($GRANT,true);
					if( isset($tokenData['token_type']) && strcasecmp('bearer',$tokenData['token_type']) == 0) 
					{
						$this->setAuthFlag(OAuthBase::AUTH_BEARER);
					}
					if( isset($tokenData['access_token']) ) $this->setAccessToken($tokenData['access_token']);
					if( isset($tokenData['refresh_token']) ) $this->setRefreshToken($tokenData['refresh_token']);
					if( isset($tokenData['expires_in']) ) $this->setAccessTokenExpiry(date('Y-m-d H:i:s',strtotime('+' . $tokenData['expires_in'] . ' seconds')));
					$this->retrieveUserData();
				}
				catch(Exception $e)
				{
					die($e->getMessage());
				}
			}
		}
	}
	protected function processResource($RESOURCE)
	{
	}
	function retrieveUserData()
	{
		$c = curl_init('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getUserInfoEndpoint());
		curl_setopt($c,CURLOPT_USERAGENT,$this->getUserAgentString());
		if( $this->getSSLTLS() )
		{
			if( defined('CURL_SSLVERSION_TLSv1_2') ) curl_setopt($c,CURLOPT_SSLVERSION,CURL_SSLVERSION_TLSv1_2);
			elseif( defined('CURL_SSLVERSION_TLSv1_1') ) curl_setopt($c,CURLOPT_SSLVERSION,CURL_SSLVERSION_TLSv1_1);
			curl_setopt($c,CURLOPT_SSL_VERIFYHOST,2);
			if(version_compare(PHP_VERSION,'7.0.7','>=') && defined('CURL_SSL_VERIFYSTATUS')) curl_setopt($c,CURL_SSL_VERIFYSTATUS,true);
		}
		curl_setopt($c,CURLOPT_RETURNTRANSFER,true);
		$param = array();
		$headers = array();
		if( $this->checkAuthFlag(OAuthBase::AUTH_BEARER) && is_null($this->getAccessToken()) === false )
		{
			$headers[] = 'Authorization: Bearer ' . $this->getAccessToken();
		}
		if( ! empty($headers) ) curl_setopt($c,CURLOPT_HTTPHEADER,$headers);
		$data = curl_exec($c);
		curl_close($c);
	}
}
