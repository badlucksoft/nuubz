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
	\brief Demonstration receiver and processing code.
	
	This code is demonstration code showing how to process the received OAuth2 response.
*/

require_once 'oauthgoogle.class.php';
// We need the OAuthBase subclass in a session variable to proceed, so only go ahead if we have
// the session cookie.
if( isset($_COOKIE[session_name()]) ) 
{
	// Start the session, with some measure of safety
	if( session_id() == '') session_start();
	
	// We should receive state and code arguments from the OAuth2 provider.
	if(  isset($_GET['state']) && isset($_GET['code']))
	{
		if( isset($_SESSION['oauth_provider']) && $_SESSION['oauth_provider'] instanceof OAuthBase)
		{
			$oauth =& $_SESSION['oauth_provider'];
			if( $oauth->verifyAuthorizationState($_GET['state']) )
			{
				$oauth->setAuthorizationCode($_GET['code']);
				try{
					$oauth->authenticate();
					/*
					If everything goes according to plan, the OAuthBase subclass
					will authenticate the credentials received, and call its
					processAuthGrant() function, which in turn will call its
					retrieveUserData() function. Once this has been done successfully
					the requested user data will be available through the 
					subclass. (Still to be implemented.)
					*/
					die('Successfully authenticated, ready to retrieve user information.');
				}
				catch(OAuthException $e)
				{
					//you can handle OAuth exceptions here.
					die($e->getMessage());
				}
				catch(Exception $e)
				{
					//other exceptions
					die($e->getMessage());
				}
			}
			else die('Authorization state failed verification.');
		}
		else die('The OAuthBase subclass object appears to be missing from the session.');
	}
	else die('Either the state, code, or both arguments from the provider is/are missing.');
}
else die('Establish a session first to contain the OAuthBase subclass object; the initiator.php would do the trick.');