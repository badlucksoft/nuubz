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
		parent::setAuthorizeEndpoint('accounts.google.com/o/oauth2/v2/auth');
		parent::setTokenEndpoint('www.googleapis.com/oauth2/v4/token');
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.email');
		$this->addResourceScope('https://www.googleapis.com/auth/userinfo.profile');
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
	protected function processResource($RESOURCE)
	{
	}
}
