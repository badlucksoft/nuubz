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
	\brief Contains class OAuthTwitch
	
	\class OAuthTwitch
	\brief Twitch subclass
	
	This is the subclass that will handle Twitch OAuth2 communications.
	
	\todo Everything.
*/

class OAuthTwitch extends OAuthBase
{
	const TWITCH_API_VERSION = 5;
	private $use_api_version = OAuthTwitch::TWITCH_API_VERSION;
	function __construct()
	{
		parent::__construct();
		parent::setServiceName('Twitch');
		parent::setAuthorizeEndpoint('api.twitch.tv/kraken/oauth2/authorize');
		parent::setTokenEndpoint('api.twitch.tv/kraken/oauth2/token');
		parent::setSSLTLS(true);
		$this->scopeSeparator = ' ';
		$this->addResourceScope('channel_feed_read');
		$this->addResourceScope('channel_read');
		$this->addResourceScope('user_read');
		$this->addHeader('Accept',$this->getMIMEType());
	}
	function getMIMEType()
	{
		return 'application/vnd.twitchtv.v' . $this->use_api_version .'+json';
	}
	function processAuthGrant($GRANT,$TYPE)
	{
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
					die('<br>end');
				}
				catch(Exception $e)
				{
					die($e->getMessage());
				}
			}
		}
	}
	function processResource($RESOURCE)
	{
	}
}