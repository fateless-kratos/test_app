"""
Utilities for generating Slack app installation links and handling installations
"""

import urllib.parse
from config import Config
from logger_setup import logger

def generate_slack_install_url(team_id=None):
    """
    Generate URL for installing the Slack app to a workspace
    
    Args:
        team_id (str, optional): Specific team ID if reinstalling
        
    Returns:
        str: Slack app installation URL
    """

    scopes = [
        "chat:write",
        "chat:write.public", 
        "commands",
        "app_mentions:read",
        "im:history",
        "channels:history"
    ]
    

    params = {
        'client_id': Config.SLACK_CLIENT_ID,
        'scope': ','.join(scopes),
        'redirect_uri': Config.SLACK_REDIRECT_URI
    }
    
   
    if team_id:
        params['team'] = team_id
    
  
    install_url = f"https://slack.com/oauth/v2/authorize?{urllib.parse.urlencode(params)}"
    logger.debug(f"Generated Slack installation URL: {install_url}")
    
    return install_url

def create_install_button_html():
    """
    Create HTML for "Add to Slack" button
    
    Returns:
        str: HTML for the "Add to Slack" button
    """
    install_url = generate_slack_install_url()
    
    button_html = f"""
    <a href="{install_url}">
        <img 
            alt="Add to Slack" 
            height="40" 
            width="139" 
            src="https://platform.slack-edge.com/img/add_to_slack.png" 
            srcset="https://platform.slack-edge.com/img/add_to_slack.png 1x, https://platform.slack-edge.com/img/add_to_slack@2x.png 2x"
        />
    </a>
    """
    
    return button_html
