"""Handles OAuth session management using Firestore"""

import uuid
import time
from firestore_client import FirestoreClient
from logger_setup import logger

def create_oauth_session(user_id, thread_ts=None, channel_id=None, team_id=None, extra_data=None):
    """Create a secure OAuth session in Firestore"""
    try:
        session_id = str(uuid.uuid4())
        client = FirestoreClient()
        
        # Clean up any expired sessions first
        cleanup_expired_sessions()
        
        # Also clean up any old sessions for this user (keep things tidy)
        cleanup_oauth_sessions(user_id)
        
        # Reduce session expiry to 30 minutes
        expiry = int(time.time()) + 1800  # 30 minutes in seconds
        
        session_data = {
            'user_id': user_id,
            'thread_ts': thread_ts,
            'channel_id': channel_id,
            'team_id': team_id,  # Store team_id in the session
            'created_at': time.time(),
            'expires_at': expiry,
            'extra_data': extra_data or {}
        }
        
        # Store in Firestore
        client.db.collection('oauth_sessions').document(session_id).set(session_data)
        
        logger.debug(f"Created OAuth session {session_id} for user {user_id} in team {team_id or 'unknown'}")
        
        return session_id
        
    except Exception as e:
        logger.error(f"Error creating OAuth session: {str(e)}")
        return None

def get_oauth_session(session_id):
    """Retrieve and validate an OAuth session"""
    try:
        client = FirestoreClient()
        session_doc = client.db.collection('oauth_sessions').document(session_id).get()
        
        if not session_doc.exists:
            logger.warning(f"OAuth session {session_id} not found")
            return None
            
        session_data = session_doc.to_dict()
        
        # Check expiration
        if session_data['expires_at'] < time.time():
            logger.warning(f"OAuth session {session_id} has expired")
            return None
            
        return session_data
        
    except Exception as e:
        logger.error(f"Error retrieving OAuth session: {str(e)}")
        return None

def cleanup_expired_sessions():
    """Clean up expired OAuth sessions from Firestore"""
    try:
        client = FirestoreClient()
        current_time = time.time()
        
        # Get all sessions that have expired
        expired_sessions = (
            client.db.collection('oauth_sessions')
            .where('expires_at', '<', current_time)
            .limit(100)  # Process in batches
            .get()
        )
        
        # Delete expired sessions
        batch = client.db.batch()
        count = 0
        
        for session in expired_sessions:
            batch.delete(session.reference)
            count += 1
            
            # Commit every 500 deletes (Firestore batch limit)
            if count == 500:
                batch.commit()
                batch = client.db.batch()
                count = 0
                
        # Commit any remaining deletes
        if count > 0:
            batch.commit()
            
        logger.info(f"Cleaned up {count} expired OAuth sessions")
        
    except Exception as e:
        logger.error(f"Error cleaning up expired sessions: {str(e)}")

def cleanup_oauth_sessions(user_id=None):
    """
    Clean up OAuth sessions for a specific user or all used/expired sessions
    
    Args:
        user_id (str, optional): Specific user to clean up sessions for
    """
    try:
        client = FirestoreClient()
        current_time = time.time()
        batch = client.db.batch()
        count = 0
        
        # Create query based on parameters
        if user_id:
            # Get all sessions for this user
            query = client.db.collection('oauth_sessions').where('user_id', '==', user_id)
        else:
            # Get all expired or used sessions
            query = client.db.collection('oauth_sessions').where('expires_at', '<', current_time)
            
        sessions = query.limit(100).get()
        
        # Delete sessions in batch
        for session in sessions:
            batch.delete(session.reference)
            count += 1
            
            # Firestore has a limit of 500 operations per batch
            if count == 500:
                batch.commit()
                batch = client.db.batch()
                count = 0
                
        # Commit any remaining operations
        if count > 0:
            batch.commit()
            
        logger.info(f"Cleaned up {count} OAuth sessions" + (f" for user {user_id}" if user_id else ""))
        return count
        
    except Exception as e:
        logger.error(f"Error cleaning up OAuth sessions: {str(e)}")
        return 0

def delete_oauth_session(session_id):
    """
    Delete a specific OAuth session by ID
    
    Args:
        session_id (str): The session ID to delete
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = FirestoreClient()
        client.db.collection('oauth_sessions').document(session_id).delete()
        logger.info(f"Deleted OAuth session: {session_id}")
        return True
    except Exception as e:
        logger.error(f"Error deleting OAuth session {session_id}: {str(e)}")
        return False