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
	\file
	\brief Demonstration initiator.
	
	This code is demonstration code showing one way to initiate the OAuth2 authentication process.
	This is relatively simple code designed to trigger the authentication process using redirection via
	PHP's header() call. It can be reused multiple times as it will destroy the existing session when
	reused. You may need to deauthorize your site between tests, however, at the provider side.
	
	To use this code, place it in the same directory as oauth.class.php and oauthfacebook.class.php 
*/

ob_start();
require_once 'oauth.class.php';
if( isset($_COOKIE[session_name()]) )
{
	session_destroy();
	setcookie(session_name(),'nothing',strtotime('-1 day'),'/',ini_get('session.cookie_domain'));
	header('Location: initiator.php',true, 302);
	exit();
}
if(session_id() == '') session_start();
$_SESSION['oauth_provider'] = new OAuthFacebook();
$_SESSION['oauth_provider']->setClientID('your client id');
$_SESSION['oauth_provider']->setClientSecret('your client secret');
$_SESSION['oauth_provider']->setAuthorizeRedirectURI('yourdomainhere/receiverscript');
header('Location: http://' . $_SESSION['oauth_provider']->authRedirectResourceOwner(),true,302);
