"""
Helper functions for OAuth authorization flows.
"""

import urllib.parse
import base64
import json
from config import Config
from logger_setup import logger
from firestore_client import get_user_tokens
from oauth_session import create_oauth_session

def user_needs_authorization(user_id):
    """
    Check if a user needs authorization
    
    Args:
        user_id (str): Slack user ID
        
    Returns:
        bool: True if user needs authorization, False otherwise
    """
    # Check if user has tokens in Firestore
    user_tokens = get_user_tokens(user_id)
    if not user_tokens:
        logger.info(f"User {user_id} needs authorization")
        return True
    
    # User has tokens, no authorization needed
    logger.debug(f"User {user_id} is already authorized")
    return False

def generate_auth_url(user_id, redirect_uri=None, thread_ts=None, channel_id=None, team_id=None):
    """Generate an OAuth authorization URL using server-side sessions"""
    try:
        # Create secure session
        session_id = create_oauth_session(
            user_id=user_id,
            thread_ts=thread_ts,
            channel_id=channel_id,
            team_id=team_id,
            extra_data={'source': 'dealmaker_auth'}
        )
        
        if not session_id:
            logger.error("Failed to create OAuth session")
            return None
            
        # Build auth parameters with session ID as state
        params = {
            'client_id': Config.OAUTH_CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': Config.OAUTH_REDIRECT_URI,
            'scope': Config.OAUTH_SCOPE,
            'state': session_id,
            'prompt': 'consent',
            'access_type': 'offline'
        }
        
        # Generate the authorization URL
        auth_url = f"{Config.OAUTH_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
        logger.debug(f"Generated auth URL with session {session_id}")
        
        return auth_url
        
    except Exception as e:
        logger.error(f"Error generating auth URL: {str(e)}")
        return None

def create_auth_request_response(user_id, thread_ts=None, channel_id=None, team_id=None):
    """
    Create a simulated Dialogflow response prompting for authorization
    
    Args:
        user_id (str): Slack user ID
        thread_ts (str, optional): Thread timestamp for contextual responses
        channel_id (str, optional): Channel ID for contextual responses
        team_id (str, optional): Slack team ID
        
    Returns:
        dict: Simulated Dialogflow response with authorization message
    """
    auth_url = generate_auth_url(user_id, thread_ts=thread_ts, channel_id=channel_id, team_id=team_id)
    
    # Create a response that looks like a Dialogflow response
    response = {
        "responseId": "auth-required",
        "queryResult": {
            "responseMessages": [
                {
                    "text": {
                        "text": [
                            f"You need to connect your Dealmaker account before I can assist you. "
                            f"Once connected, you can say 'Hi' to get started!"
                        ]
                    }
                },
                {
                    "text": {
                        "text": [
                            f"<{auth_url}|Connect your Dealmaker account>"
                        ]
                    }
                }
            ],
            "parameters": {
                "requires_auth": True,
                "thread_ts": thread_ts,
                "channel_id": channel_id,
                "team_id": team_id
            }
        }
    }
    
    return response
