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
	\brief Contains class OAuthFacebook
	\class OAuthFacebook
	\brief Facebook subclass
	
	This is the subclass that will handle Facebook OAuth2 communications.
	
	\todo Everything.
*/
class OAuthFacebook extends OAuthBase
{
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Facebook');
		parent::setAuthorizeEndpoint('www.facebook.com/v3.2/dialog/oauth');
		parent::setTokenEndpoint('graph.facebook.com/v3.2/oauth/access_token');
		//parent::setResourceServerURL('somethingelseatfacebook');
		parent::setUserInfoEndpoint('graph.facebook.com/me');
		$this->scopeSeparator = ',';
		$this->addResourceScope('email');
		$this->addResourceScope('public_profile');
	}
	function getUserIDFieldName()
	{
		return 'id';
	}
	function getGivenNameFieldName()
	{
		return 'first_name';
	}
	function getFamilyNameFieldName()
	{
		return 'last_name';
	}
	function getEmailFieldName()
	{
		return 'email';
	}
	function getUserNameFieldName()
	{
		return null;
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
					//if( ! is_null($this->getAccessToken()) ) echo 'successfully obtained access token!';
					//die('<br>end');
					$this->retrieveUserData();
				}
				catch(Exception $e)
				{
					die($e->getMessage());
				}
			}
		}
		$vars = array('client_id' => urlencode($this->getClientID()), 'client_secret' => urlencode($this->getClientSecret()),'redirect_uri' => urlencode('http' . ($this->getSSLTLS() ? 's':'') . '://' . $this->getAuthorizeRedirectURI()),'code' => null);
		
	}
	function retrieveUserData()
	{
		//echo 'retrieveUserData()<br>';

		$c = curl_init('http' . ($this->getSSLTLS() ? 's':'') . '://'. $this->getUserInfoEndpoint() . '?access_token=' . $this->getAccessToken() . '&fields=id,first_name,last_name,email'  );
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
		//echo 'curl error: ' . curl_error($c) . '<br>'; 
		curl_close($c);
		//echo 'data:<br>';
		//preout($data);
		if( ! empty($data) )
		{
			$this->user_data = json_decode($data);
			$this->user_first_name = $this->user_data->first_name;
			$this->user_last_name = $this->user_data->last_name;
			$this->user_email = $this->user_data->email;
			$this->user_id = $this->user_data->id;
		}
	}
	protected function processResource($RESOURCE)
	{
	}
}
