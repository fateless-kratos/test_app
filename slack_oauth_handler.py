"""
Handler for Slack OAuth flow for app installations
"""

import requests
from config import Config
from logger_setup import logger

def process_slack_oauth(code, redirect_uri=None):
    """
    Process Slack OAuth callback to complete app installation
    
    Args:
        code (str): Authorization code from Slack
        redirect_uri (str, optional): Redirect URI used in the auth request
        
    Returns:
        dict: Installation data with tokens or None if failed
    """
    try:
        if not redirect_uri:
            redirect_uri = Config.SLACK_REDIRECT_URI
            
        # Exchange the code for access token
        response = requests.post(
            "https://slack.com/api/oauth.v2.access",
            data={
                "client_id": Config.SLACK_CLIENT_ID,
                "client_secret": Config.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri
            }
        )
        
        response.raise_for_status()
        data = response.json()
        
        if not data.get("ok", False):
            logger.error(f"Slack OAuth error: {data.get('error')}")
            return None

        # Check if response contains data
        if not data or not isinstance(data, dict):
            logger.error(f"Invalid response from Slack OAuth: {data}")
            return None
            
        # Safely get enterprise ID with proper null checking
        enterprise = data.get("enterprise", {})
        enterprise_id = enterprise.get("id") if enterprise else None
        
        # Get team ID safely
        team = data.get("team", {})
        team_id = team.get("id") if team else None
        
        # Log successful installation
        if team_id:
            logger.info(f"App installed to team {team_id}")
        if enterprise_id:
            logger.info(f"App installed to enterprise {enterprise_id}")
        
        # Check for authed_user data
        authed_user = data.get("authed_user", {})
        if not authed_user:
            logger.warn(f"No authed_user data in Slack OAuth response")
        
        # Process user data if available
        user_id = authed_user.get("id") if authed_user else None
        access_token = authed_user.get("access_token") if authed_user else None
        
        return data
    
    except Exception as e:
        logger.error(f"Error processing Slack OAuth: {str(e)}", exc_info=True)
        return None

def store_installation(installation_data):
    """
    Store Slack app installation data in Firestore
    
    Args:
        installation_data (dict): Data from Slack OAuth response
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not installation_data:
            logger.error("No installation data to store")
            return False
            
        # Import here to avoid circular imports
        from firestore_client import FirestoreClient
        from firebase_admin import firestore
        
        # Get identifiers
        team = installation_data.get("team", {})
        team_id = team.get("id") if team else None
        team_name = team.get("name") if team else None
        
        enterprise = installation_data.get("enterprise", {})
        enterprise_id = enterprise.get("id") if enterprise else None
        enterprise_name = enterprise.get("name") if enterprise else None
        
        # Create a document ID - either enterprise_id.team_id or just team_id
        doc_id = f"{enterprise_id}.{team_id}" if enterprise_id else team_id
        
        if not doc_id:
            logger.error("Could not determine installation ID")
            return False
            
        # Check if this is a reinstallation
        client = FirestoreClient()
        existing_doc = client.db.collection('slack_installations').document(doc_id).get()
        if existing_doc.exists:
            logger.info(f"Found existing installation for {doc_id} - updating")
            
            # Add extra metadata
            installation_data["updated_at"] = firestore.SERVER_TIMESTAMP
            installation_data["is_update"] = True
            
            # Might want to merge with existing data or overwrite
            client.db.collection('slack_installations').document(doc_id).set(
                installation_data, merge=True
            )
        else:
            # First-time installation
            logger.info(f"New installation for {doc_id}")
            installation_data["installed_at"] = firestore.SERVER_TIMESTAMP 
            installation_data["is_update"] = False
            client.db.collection('slack_installations').document(doc_id).set(installation_data)
        
        # Store token separately for quick access
        # Get the bot token from the correct location based on the Slack API response structure
        bot_token = installation_data.get("access_token")  # For most modern apps
        
        # For classic Slack apps, the token might be in a different location
        if not bot_token:
            bot = installation_data.get("bot", {})
            if bot:
                bot_token = bot.get("bot_access_token")
                
        # For user tokens in the authed_user section
        authed_user = installation_data.get("authed_user", {})
        user_token = authed_user.get("access_token") if authed_user else None
        
        if bot_token:
            token_data = {
                "bot_token": bot_token,
                "user_token": user_token,
                "team_id": team_id,
                "team_name": team_name,
                "enterprise_id": enterprise_id,
                "enterprise_name": enterprise_name,
                "installed_at": firestore.SERVER_TIMESTAMP,
                "updated_at": firestore.SERVER_TIMESTAMP
            }
            client.db.collection('slack_tokens').document(doc_id).set(token_data)
            logger.info(f"Stored bot token for {doc_id}")
        else:
            logger.warning(f"No bot token found in installation data for {doc_id}")
            
        # Check and cleanup any duplicate installations
        check_and_clean_duplicate_installations(client, team_id, enterprise_id, doc_id)
        
        logger.info(f"Slack installation stored successfully for {doc_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error storing installation data: {str(e)}", exc_info=True)
        return False

def check_and_clean_duplicate_installations(client, team_id, enterprise_id, current_doc_id):
    """
    Check for duplicate installations and clean them up
    
    Args:
        client: Firestore client
        team_id: Slack team ID
        enterprise_id: Enterprise grid ID
        current_doc_id: Current installation document ID
    """
    try:
        # Query tokens for the same team
        query = client.db.collection('slack_tokens')
        
        if enterprise_id:
            query = query.where('enterprise_id', '==', enterprise_id)
        
        if team_id:
            query = query.where('team_id', '==', team_id)
            
        results = query.get()
        
        for doc in results:
            doc_id = doc.id
           
            if doc_id == current_doc_id:
                continue
                
            # Found a duplicate - mark it as inactive
            logger.warning(f"Found duplicate installation: {doc_id}")
            client.db.collection('slack_tokens').document(doc_id).update({
                'active': False,
                'replaced_by': current_doc_id,
                'replaced_at': firestore.SERVER_TIMESTAMP
            })
    except Exception as e:
        logger.error(f"Error checking for duplicate installations: {str(e)}")
