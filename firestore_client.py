"""
Firestore client for storing Slack installation data and other state
"""

import os
import firebase_admin
from firebase_admin import credentials, firestore
from config import Config
from logger_setup import logger

class FirestoreClient:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize the Firestore client"""
        try:
            # Initialize Firebase app if not already initialized
            if not firebase_admin._apps:
                cred_path = Config.GOOGLE_APPLICATION_CREDENTIALS
                
                if os.path.exists(cred_path):
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(
                        cred, 
                        {'databaseURL': Config.FIREBASE_DATABASE_URL}
                    )
                else:
                    logger.error(f"Google credentials file not found at {cred_path}")
                    raise FileNotFoundError(f"Credentials file not found: {cred_path}")
            
            self.db = firestore.client()
            logger.info("Firestore client initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing Firestore client: {str(e)}", exc_info=True)
            raise
    
    def get_installation(self, team_id, enterprise_id=None):
        """
        Get Slack installation data
        
        Args:
            team_id (str): Slack team ID
            enterprise_id (str, optional): Enterprise grid ID
            
        Returns:
            dict: Installation data or None if not found
        """
        try:
            doc_id = f"{enterprise_id}.{team_id}" if enterprise_id else team_id
            doc_ref = self.db.collection('slack_installations').document(doc_id)
            doc = doc_ref.get()
            
            if doc.exists:
                return doc.to_dict()
            else:
                logger.warning(f"No installation found for {doc_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving installation data: {str(e)}", exc_info=True)
            return None
    
    def get_bot_token(self, team_id, enterprise_id=None):
        """
        Get bot token for a workspace with additional logging
        
        Args:
            team_id (str): Slack team ID
            enterprise_id (str, optional): Enterprise grid ID
            
        Returns:
            str: Bot token or None if not found
        """
        try:
            doc_id = f"{enterprise_id}.{team_id}" if enterprise_id else team_id
            logger.debug(f"Looking up bot token for {doc_id}")
            
            # First try the direct lookup
            doc_ref = self.db.collection('slack_tokens').document(doc_id)
            doc = doc_ref.get()
            
            if doc.exists:
                data = doc.to_dict()
                token = data.get('bot_token')
                
                # Check if this token is marked as inactive
                if data.get('active') is False:
                    replacement = data.get('replaced_by')
                    logger.warning(f"Found inactive token for {doc_id}, replaced by {replacement}")
                    
                    # Try to get the replacement
                    if replacement:
                        replacement_doc = self.db.collection('slack_tokens').document(replacement).get()
                        if replacement_doc.exists:
                            replacement_data = replacement_doc.to_dict()
                            return replacement_data.get('bot_token')
                
                return token
            
            # If direct lookup fails, try a query
            logger.debug(f"No token found with exact ID {doc_id}, trying query")
            query = self.db.collection('slack_tokens')
            
            if team_id:
                query = query.where('team_id', '==', team_id)
            
            if enterprise_id:
                query = query.where('enterprise_id', '==', enterprise_id)
                
            # Only get active tokens
            query = query.where('active', '==', True)
            
            results = query.get()
            
            if not results:
                logger.warning(f"No tokens found for team_id={team_id}, enterprise_id={enterprise_id}")
                return None
                
            # If multiple results, use the most recently updated
            if len(results) > 1:
                logger.warning(f"Multiple tokens found for team_id={team_id}, enterprise_id={enterprise_id}")
                # Get the most recent
                most_recent = None
                most_recent_time = None
                
                for doc in results:
                    data = doc.to_dict()
                    updated_at = data.get('updated_at')
                    
                    if not most_recent or (updated_at and updated_at > most_recent_time):
                        most_recent = data
                        most_recent_time = updated_at
                        
                if most_recent:
                    return most_recent.get('bot_token')
            
            # Just one result
            return results[0].to_dict().get('bot_token')
                    
        except Exception as e:
            logger.error(f"Error retrieving bot token: {str(e)}", exc_info=True)
            return None

def get_user_tokens(user_id):
    """
    Retrieve user tokens from Firestore
    
    Args:
        user_id (str): Slack user ID
        
    Returns:
        dict: User tokens or None if not found
    """
    try:
        client = FirestoreClient()
        user_doc = client.db.collection('oauth_tokens').document(user_id).get()
        
        if user_doc.exists:
            logger.info(f"Retrieved tokens for user: {user_id}")
            return user_doc.to_dict()
        else:
            logger.warning(f"No tokens found for user: {user_id}")
            return None
            
    except Exception as e:
        logger.error(f"Error retrieving user tokens: {str(e)}", exc_info=True)
        return None

def update_user_tokens(user_id, token_data):
    """
    Update or create user tokens in Firestore
    
    Args:
        user_id (str): Slack user ID
        token_data (dict): Token information to store
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = FirestoreClient()
        
        # Update the document, creating it if it doesn't exist
        client.db.collection('oauth_tokens').document(user_id).set(
            token_data, 
            merge=True  # Use merge to update only provided fields
        )
        
        logger.info(f"Updated token data for user: {user_id}")
        return True
            
    except Exception as e:
        logger.error(f"Error updating user tokens: {str(e)}", exc_info=True)
        return False

