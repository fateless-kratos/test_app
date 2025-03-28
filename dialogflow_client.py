import requests
import json
import time
import google.auth
import google.auth.transport.requests
from authlib.integrations.requests_client import OAuth2Session
from config import Config
from logger_setup import logger
from firestore_client import get_user_tokens, update_user_tokens
from metrics import track_dialogflow_call
from auth_helper_slack import user_needs_authorization, create_auth_request_response

class DialogflowClient:
    def __init__(self):
        logger.info("Initializing Dialogflow client")
    
    def get_google_access_token(self):
        """Get Google access token for Dialogflow API requests"""
        try:
            credentials, project = google.auth.default(
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            auth_req = google.auth.transport.requests.Request()
            credentials.refresh(auth_req)
            logger.debug("Successfully obtained Google access token")
            return credentials.token
        except Exception as e:
            logger.error(f"Failed to get Google access token: {str(e)}", exc_info=True)
            raise
    
    def refresh_oauth_token(self, refresh_token, user_id):
        """
        Refresh an expired OAuth token using the refresh token
        
        Args:
            refresh_token (str): The refresh token to use
            user_id (str): User ID for storage and logging
            
        Returns:
            str: New access token if successful, None otherwise
        """
        try:
            logger.info(f"Attempting to refresh access token for user {user_id}")
            
            # Create OAuth2Session for refreshing token
            oauth = OAuth2Session(
                client_id=Config.OAUTH_CLIENT_ID,
                client_secret=Config.OAUTH_CLIENT_SECRET,
                token_endpoint=Config.OAUTH_TOKEN_ENDPOINT
            )
            
            # Request new token using refresh token
            token_data = oauth.refresh_token(
                Config.OAUTH_TOKEN_ENDPOINT,
                refresh_token=refresh_token
            )
            
            # Extract new tokens
            new_access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token', refresh_token)  
            expires_in = token_data.get('expires_in', 3600)
            
            # Calculate expiration time
            expiry_time = int(time.time()) + expires_in
            
            # Save updated tokens
            token_info = {
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'expires_at': expiry_time
            }
            update_user_tokens(user_id, token_info)
            
            logger.info(f"Successfully refreshed access token for user {user_id}")
            logger.debug(f"Token expires in {expires_in} seconds")
            
            return new_access_token
            
        except Exception as e:
            logger.error(f"Failed to refresh access token for user {user_id}: {str(e)}", exc_info=True)
            return None
    
    @track_dialogflow_call
    def process_dialogflow_request(self, text, user, thread_id=None, channel_id=None, team_id=None):
        """
        Process a request to Dialogflow
        
        Args:
            text (str): The user's message text
            user (str): The user's ID for session management
            thread_id (str, optional): Thread ID for channel conversations
            channel_id (str, optional): Channel ID for responses
            team_id (str, optional): Slack team ID
            
        Returns:
            dict: The Dialogflow response data or authorization request
        """
        # First, check if user needs authorization
        if user_needs_authorization(user):
            logger.info(f"User {user} needs authorization, returning auth request instead of Dialogflow call")
            # Return a simulated Dialogflow response with auth request including thread context
            return create_auth_request_response(
                user_id=user, 
                thread_ts=thread_id, 
                channel_id=channel_id,
                team_id=team_id
            )
        
        # Create a session ID that combines user ID and thread ID for thread-based context
        session_id = user
        if thread_id:
            session_id = f"{user}_{thread_id}"
            
        logger.info(f"Processing Dialogflow request for user: {user}, session: {session_id}")
        logger.debug(f"Input text: {text}")
        
        try:
            # Get the user's access token from Firestore
            user_tokens = get_user_tokens(user)
            
            # Check if tokens exist and if we need to handle refresh
            if user_tokens:
                access_token = user_tokens.get('access_token')
                refresh_token = user_tokens.get('refresh_token')
                expires_at = user_tokens.get('expires_at', 0)
                
                # Check if token exists and if it's expired
                current_time = int(time.time())
                is_expired = current_time >= expires_at if expires_at else True
                
                if not access_token or is_expired:
                    logger.info(f"Access token for user {user} is {'expired' if is_expired else 'missing'}")
                    
                    # Try refreshing if we have a refresh token
                    if refresh_token:
                        access_token = self.refresh_oauth_token(refresh_token, user)
                    else:
                        logger.warning(f"No refresh token available for user {user}")
                        access_token = None
            else:
                access_token = None
            
            # Use the user-specific token if available, otherwise fall back to the default token
            user_access_token = access_token if access_token else Config.CLIENT_ACCESS_TOKEN
            
            if not access_token:
                logger.warning(f"Using default client access token for user {user}")
            
            google_access_token = self.get_google_access_token()
            session_path = f"projects/{Config.DIALOGFLOW_PROJECT_ID}/locations/{Config.DIALOGFLOW_LOCATION}/agents/{Config.DIALOGFLOW_AGENT_ID}/sessions/{session_id}"
            logger.debug(f"Session path: {session_path}")

            payload = {
                "session": session_path,
                "queryInput": {
                    "text": {"text": text},
                    "languageCode": "en-US"
                },
                "queryParams": {
                    "parameters": {"access_token": user_access_token}
                }
            }
            logger.debug(f"Request payload: {json.dumps(payload, indent=2)}")

            headers = {
                "Authorization": f"Bearer {google_access_token}",
                "Content-Type": "application/json"
            }
            logger.debug("Headers prepared (auth token hidden)")

            url = f"https://{Config.DIALOGFLOW_LOCATION}-dialogflow.googleapis.com/v3/{session_path}:detectIntent"
            logger.info(f"Sending request to Dialogflow: {url}")
            
            response = requests.post(
                url, 
                json=payload, 
                headers=headers,
                timeout=Config.REQUEST_TIMEOUT
            )
            logger.debug(f"Dialogflow response status: {response.status_code}")
            
            response.raise_for_status()
            response_data = response.json()
            logger.info(f"Successfully received Dialogflow response for session: {session_id}")
            
            # Log response without sensitive data
            self._log_sanitized_response(response_data)
            
            return response_data

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP Request failed: {str(e)}", exc_info=True)
            logger.error(f"Response content: {e.response.content if hasattr(e, 'response') else 'No response content'}")
            raise
        except Exception as e:
            logger.error(f"Failed to process Dialogflow request: {str(e)}", exc_info=True)
            raise
    
    def _log_sanitized_response(self, response_data):
        """Log response data with extra debug info for execution summary"""
        try:
            # Create a pretty-formatted version for logging
            pretty_json = json.dumps(response_data, indent=2)
            logger.debug(f"Dialogflow response structure: {pretty_json}")
            
            # Log a warning if there's a discrepancy between execution_summary and actual response
            if 'queryResult' in response_data and 'parameters' in response_data['queryResult']:
                params = response_data['queryResult']['parameters']
                if 'execution_summary' in params and 'responseMessages' in response_data['queryResult']:
                    exec_summary = params.get('execution_summary')
                    if "sorry" in exec_summary.lower() or "not have access" in exec_summary.lower():
                        logger.warning(f"Execution summary contains an error message but response messages exist: '{exec_summary}'")
                        logger.warning("This is likely a misleading parameter. The actual response will be used.")
            
        except Exception as e:
            logger.warning(f"Could not log response: {str(e)}")
    
    def extract_response_message(self, dialogflow_response):
        """
        Extract ALL response messages from Dialogflow response and concatenate them.
        Ignores misleading execution_summary parameter.
        
        Args:
            dialogflow_response (dict): The full Dialogflow response
            
        Returns:
            str: The concatenated text responses to send back to the user
        """
        try:
            # Log the full response for debugging
            logger.debug(f"Extracting messages from response: {json.dumps(dialogflow_response, indent=2)}")
            
            messages = []
            
            if 'queryResult' in dialogflow_response:
         
                if 'responseMessages' in dialogflow_response['queryResult']:
                    for message in dialogflow_response['queryResult']['responseMessages']:
                        if 'text' in message and message['text'].get('text'):
                            # Add each text message to our list
                            messages.extend(message['text']['text'])
                
       
                if not messages and 'fulfillmentText' in dialogflow_response['queryResult']:
                    messages.append(dialogflow_response['queryResult']['fulfillmentText'])
                

                if not messages and 'queryText' in dialogflow_response['queryResult']:
                    query = dialogflow_response['queryResult'].get('queryText')
                    messages.append(f"I received your message: '{query}', but I'm not sure how to respond.")
            
            if not messages:
                logger.warning("No response messages found in Dialogflow response")
                messages.append("I'm sorry, I couldn't process your request.")
            
            # Join all messages with newlines between them
            combined_message = "\n\n".join(messages)
            logger.info(f"Combined response message: {combined_message}")
            
            return combined_message
            
        except Exception as e:
            logger.error(f"Error extracting response message: {str(e)}", exc_info=True)
            return "An error occurred while processing your request."
