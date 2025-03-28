"""
Utility functions for formatting messages for Slack, 
with special handling for multiple response messages from Dialogflow.
"""

import re
import json
from logger_setup import logger

def format_dialogflow_response(dialogflow_response):
    """
    Format a Dialogflow response for Slack with better visual representation
    
    Args:
        dialogflow_response (dict): The full Dialogflow response
        
    Returns:
        dict: Formatted blocks for Slack rich text
    """
    try:
        # Check if this is an auth request
        is_auth_request = False
        auth_url = None
        if 'queryResult' in dialogflow_response:
            query_result = dialogflow_response['queryResult']
            if query_result.get('parameters', {}).get('requires_auth'):
                is_auth_request = True
                # Extract auth URL from second message
                if len(query_result.get('responseMessages', [])) > 1:
                    second_msg = query_result['responseMessages'][1]
                    if 'text' in second_msg and second_msg['text'].get('text'):
                        url_text = second_msg['text']['text'][0]
                        match = re.search(r'<(https?://[^|]+)\|[^>]+>', url_text)
                        if match:
                            auth_url = match.group(1)

        # For auth requests, create a special formatted response
        if is_auth_request and auth_url:
            return {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "You need to connect your Dealmaker account before I can assist you."
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Connect Dealmaker Account",
                                    "emoji": True
                                },
                                "style": "primary",
                                "url": auth_url
                            }
                        ]
                    }
                ],
                "text": "You need to connect your Dealmaker account before I can assist you."
            }

        messages = []
        
        # Extract all messages
        if 'queryResult' in dialogflow_response:
            if 'responseMessages' in dialogflow_response['queryResult']:
                for message in dialogflow_response['queryResult']['responseMessages']:
                    if 'text' in message and message['text'].get('text'):
                        messages.extend(message['text']['text'])
        
        if not messages:
            return {"text": "I couldn't find a response to your query."}
        
        # Format as a Slack message with blocks for better visual representation
        blocks = []
        
        # Add each message as a separate section block
        for msg in messages:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": msg
                }
            })
            
            # Add a divider between messages except for the last one
            if msg != messages[-1]:
                blocks.append({"type": "divider"})
        
        return {
            "blocks": blocks,
            "text": "\n\n".join(messages)  # Fallback text
        }
        
    except Exception as e:
        logger.error(f"Error formatting response: {str(e)}", exc_info=True)
        return {"text": "An error occurred while formatting the response."}

def format_list_response(text):
    """
    Enhance list formatting for Slack
    
    Args:
        text (str): Text potentially containing lists
        
    Returns:
        str: Text with enhanced list formatting
    """
    # Convert GitHub-style lists (- item) to Slack bullet points (• item)
    text = re.sub(r'^- (.+)$', r'• \1', text, flags=re.MULTILINE)
    
    # Make numbering stand out
    text = re.sub(r'^(\d+)\. (.+)$', r'*\1.* \2', text, flags=re.MULTILINE)
    
    return text
