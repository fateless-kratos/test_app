"""
Alternative version of app.py that processes events directly without threading.
Use this if you encounter issues with the threaded version.
"""

import os
import re
import json
import time
import hashlib
import threading
from collections import OrderedDict
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from config import Config
from logger_setup import logger
from dialogflow_client import DialogflowClient
from metrics import metrics
from slack_oauth_handler import process_slack_oauth, store_installation
from firestore_client import FirestoreClient
from slack_bolt.authorization import AuthorizeResult

# Custom authorize function to fetch tokens from Firestore
def authorize(team_id, enterprise_id):
    """
    Authorize function for Slack app that fetches tokens from Firestore
    
    Args:
        team_id (str): Slack team ID
        enterprise_id (str, optional): Enterprise grid ID
        
    Returns:
        AuthorizeResult: Authorization result with bot token
    """
    firestore_client = FirestoreClient()
    bot_token = firestore_client.get_bot_token(team_id, enterprise_id)
    
    if bot_token:
        logger.info(f"Found token for team_id={team_id}, enterprise_id={enterprise_id}")
        return AuthorizeResult(
            enterprise_id=enterprise_id,
            team_id=team_id,
            bot_token=bot_token,
            bot_id=None  # This will be populated by Slack Bolt internally
        )
    else:
        logger.error(f"No token found for team_id={team_id}, enterprise_id={enterprise_id}")
        # If we have a default token, use that as fallback
        if Config.SLACK_BOT_TOKEN:
            logger.info("Using default bot token as fallback")
            return AuthorizeResult(
                enterprise_id=None,
                team_id=None,
                bot_token=Config.SLACK_BOT_TOKEN,
                bot_id=None
            )
        return None

# Initialize the Slack app
app = App(
    token=Config.SLACK_BOT_TOKEN,
    signing_secret=Config.SLACK_SIGNING_SECRET,
    authorize=authorize
)

# Initialize Dialogflow client
dialogflow_client = DialogflowClient()

# Add a function to get the bot ID
def get_bot_user_id(client):
    """Get the bot's user ID"""
    try:
        # Call the auth.test method to get information about the bot
        auth_result = client.auth_test()
        if (auth_result["ok"]):
            return auth_result["user_id"]
        else:
            logger.error(f"Failed to get bot user ID: {auth_result.get('error')}")
            return None
    except Exception as e:
        logger.error(f"Error getting bot user ID: {str(e)}", exc_info=True)
        return None

BOT_USER_ID = None

# Create a thread-safe cache for processed events
class LRUCache:
    """Thread-safe LRU cache for processed events"""
    def __init__(self, capacity=1000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = threading.Lock()
        
    def contains(self, key):
        """Check if key exists in cache"""
        with self.lock:
            return key in self.cache
            
    def put(self, key):
        """Add key to cache, removing oldest if at capacity"""
        with self.lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return
                
            self.cache[key] = True
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)  # Remove oldest item

# Create global caches for different event types
message_cache = LRUCache(capacity=500)
mention_cache = LRUCache(capacity=500)

# Helper functions and event handlers
def is_bot_mentioned(text, user_id):
    """Check if the bot is mentioned in the message"""
    return f"<@{user_id}>" in text

def remove_bot_mention(text, user_id):
    """Remove the bot mention from the message"""
    return re.sub(f"<@{user_id}>\s*", "", text).strip()

def should_process_message(message, bot_user_id):
    """Determine if the message should be processed by the bot"""
    # Create a unique message fingerprint using content and timestamp
    text = message.get("text", "")
    ts = message.get("ts", "")
    user = message.get("user", "")
    channel = message.get("channel", "")
    
    # List of bot IDs to ignore
    IGNORED_BOT_IDS = {
        'U08BD8PDCJH',  # Main bot user ID
        bot_user_id     # Dynamic bot ID from auth
    }
    
    if not text or not ts or not user:
        logger.debug("Ignoring message with missing essential data")
        return False
        
    # Ignore messages from known bot IDs
    if user in IGNORED_BOT_IDS:
        logger.debug(f"Ignoring message from bot user: {user}")
        return False
    
    # Create a unique key for this message
    fingerprint = f"{channel}:{user}:{ts}:{hashlib.md5(text.encode()).hexdigest()}"
    
    # Check if we've already processed this message
    if message_cache.contains(fingerprint):
        logger.warning(f"Duplicate message detected: {fingerprint[:20]}...")
        return False
    
    # Only process plain messages with text - ignore all message subtypes
    if message.get("subtype") is not None:
        logger.debug(f"Ignoring message with subtype: {message.get('subtype')}")
        return False
    
    # Ignore messages from bots (including our own)
    if message.get("bot_id") or message.get("user") == bot_user_id:
        logger.debug("Ignoring bot message")
        return False
    
    # Process direct messages
    if message.get("channel_type") == "im":
        logger.debug("Processing direct message")
        message_cache.put(fingerprint)
        return True
    
    # Process mentions in channels
    if is_bot_mentioned(text, bot_user_id):
        logger.debug("Processing message with bot mention")
        message_cache.put(fingerprint)
        return True
    
    # Ignore all other messages
    logger.debug("Ignoring message - doesn't meet criteria")
    return False

@app.event("message")
def handle_message_events(body, logger, client, context):
    """Handle message events from Slack"""
    global BOT_USER_ID
    
    # Get the bot ID if we don't have it yet
    if BOT_USER_ID is None:
        BOT_USER_ID = get_bot_user_id(client)
        logger.info(f"Retrieved bot user ID: {BOT_USER_ID}")
    
    # Extract the message
    event = body.get("event", {})
    event_id = body.get("event_id", "unknown")
    
    # Early check for duplicates based on event_id
    if message_cache.contains(f"event:{event_id}"):
        logger.warning(f"Duplicate event ID detected: {event_id}")
        return
    
    # Log basic event info
    logger.debug(f"Received message event ID: {event_id}, ts: {event.get('ts')}")
    
    # Check if this is a message we should respond to
    if should_process_message(event, BOT_USER_ID):
        # Add event_id to cache to prevent duplicate processing
        message_cache.put(f"event:{event_id}")
        process_and_respond_to_message(event, client, BOT_USER_ID)
    else:
        logger.debug(f"Not processing message event: {event_id}")

@app.event("app_mention")
def handle_app_mention(body, logger, client, context):
    """Handle app mention events"""
    global BOT_USER_ID
    
    # Get the bot ID if we don't have it yet
    if BOT_USER_ID is None:
        BOT_USER_ID = get_bot_user_id(client)
        logger.info(f"Retrieved bot user ID: {BOT_USER_ID}")
    
    # Extract the event
    event = body.get("event", {})
    event_id = body.get("event_id", "unknown")
    
    # Create a unique fingerprint for this mention
    text = event.get("text", "")
    ts = event.get("ts", "")
    user = event.get("user", "")
    channel = event.get("channel", "")
    
    fingerprint = f"{channel}:{user}:{ts}:{hashlib.md5(text.encode()).hexdigest()}"
    
    # Check for duplicates
    if mention_cache.contains(fingerprint) or mention_cache.contains(f"event:{event_id}"):
        logger.warning(f"Duplicate app_mention detected: {event_id}")
        return
        
    # Add to cache
    mention_cache.put(fingerprint)
    mention_cache.put(f"event:{event_id}")
    
    # Make sure the mention is not from our bot
    if event.get("user") == BOT_USER_ID:
        logger.debug("Ignoring self-mention")
        return
        
    process_and_respond_to_message(event, client, BOT_USER_ID)

def process_and_respond_to_message(event, client, bot_user_id):
    """Process the message and respond with Dialogflow, maintaining thread context"""
    try:
        user_id = event.get("user")
        channel_id = event.get("channel")
        text = event.get("text", "")
        team_id = event.get("team")  # Get team_id from the event
        
        # Skip empty messages
        if not text:
            logger.debug(f"Skipping empty message from user {user_id}")
            return
        
        # Get thread_ts for context (either existing thread or create new one)
        thread_ts = event.get("thread_ts")
        message_ts = event.get("ts")
        
        # Use the message ts as thread ts if there's no existing thread
        if not thread_ts:
            thread_ts = message_ts
            thread_id = message_ts  # Thread ID for Dialogflow
        else:
            thread_id = thread_ts  # Use existing thread ID for Dialogflow
        
        # Clean the message text (remove bot mention if present)
        if is_bot_mentioned(text, bot_user_id):
            text = remove_bot_mention(text, bot_user_id)
        
        # Send message to Dialogflow
        logger.info(f"Sending message to Dialogflow: '{text}'")
        dialogflow_response = dialogflow_client.process_dialogflow_request(
            text, 
            user_id,
            thread_id=thread_id,
            channel_id=channel_id,
            team_id=team_id
        )
        
        # Print full response to terminal for debugging in Socket Mode
        if Config.USE_SOCKET_MODE:
            print("\n" + "="*80)
            print(f"DIALOGFLOW RESPONSE FOR USER: {user_id}")
            print("="*80)
            print(json.dumps(dialogflow_response, indent=2))
            print("="*80 + "\n")
        
        # Check if this is an authorization request
        is_auth_request = False
        if 'queryResult' in dialogflow_response and 'parameters' in dialogflow_response['queryResult']:
            params = dialogflow_response['queryResult']['parameters']
            is_auth_request = params.get('requires_auth', False)
        
        # For auth requests ONLY, use the response formatter for a nice button
        if is_auth_request:
            from response_formatter import format_dialogflow_response
            
            logger.info("Authorization request detected - using formatter for button")
            formatted_response = format_dialogflow_response(dialogflow_response)
            
            # Send the formatted response with button
            client.chat_postMessage(
                channel=channel_id,
                text=formatted_response.get("text", "You need to connect your Dealmaker account"),
                blocks=formatted_response.get("blocks"),
                thread_ts=thread_ts
            )
            
            logger.info(f"Sent auth request with button to user {user_id}")
            return
        
        # For all other (non-auth) messages, extract text directly
        messages = []
        if 'queryResult' in dialogflow_response and 'responseMessages' in dialogflow_response['queryResult']:
            for message in dialogflow_response['queryResult']['responseMessages']:
                if 'text' in message and message['text'].get('text'):
                    # Add each message to our list
                    messages.extend(message['text']['text'])
        
        # If no messages were found, provide a fallback
        if not messages:
            messages = ["I'm sorry, I couldn't process your request properly."]
        
        # Join all messages with double line breaks
        full_response = "\n\n".join(messages)
        
        # Print the processed message we're going to send
        if Config.USE_SOCKET_MODE:
            print("\n" + "-"*40)
            print("SENDING TO SLACK:")
            print("-"*40)
            print(full_response)
            print("-"*40 + "\n")
        
        # Send the complete response directly to the user (without formatting for non-auth messages)
        logger.info(f"Sending response to user {user_id} in channel {channel_id}")
        
        client.chat_postMessage(
            channel=channel_id,
            text=full_response,
            thread_ts=thread_ts  # Keep the conversation in the same thread
        )
        
        logger.info(f"Successfully responded to user {user_id} in thread {thread_ts}")
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}", exc_info=True)
        
        # Send error message if we have channel and thread information
        if channel_id and (thread_ts or message_ts):
            try:
                thread_to_use = thread_ts if thread_ts else message_ts
                client.chat_postMessage(
                    channel=channel_id,
                    text="I'm sorry, I encountered an error while processing your request.",
                    thread_ts=thread_to_use
                )
            except Exception as post_error:
                logger.error(f"Failed to send error message: {str(post_error)}")

@app.command("/df_status")
def handle_status_command(ack, respond, command):
    """Handle command to check Dialogflow integration status"""
    ack()
    try:
        # Get metrics
        stats = metrics.get_metrics()
        
        # Respond with status information
        response_text = (
            f"*Dialogflow Integration Status*\n"
            f"• API Calls: {stats['api_calls']}\n"
            f"• Successful: {stats['successful_calls']}\n"
            f"• Failed: {stats['failed_calls']}\n"
            f"• Average Response Time: {stats['avg_response_time']:.2f}s\n"
        )
        
        respond(text=response_text)
        
    except Exception as e:
        logger.error(f"Error in status command: {str(e)}", exc_info=True)
        respond(text="Error retrieving status information")

def schedule_session_cleanup():
    """Schedule periodic cleanup of expired OAuth sessions"""
    from oauth_session import cleanup_expired_sessions
    
    def cleanup_task():
        while True:
            try:
                cleanup_expired_sessions()
                # Run cleanup every 15 minutes
                time.sleep(900)
            except Exception as e:
                logger.error(f"Error in cleanup task: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying on error
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    logger.info("OAuth session cleanup task scheduled")

def start_app():
    """Start the Slack application"""
    try:
        # Start the session cleanup task
        schedule_session_cleanup()
        
        if Config.USE_SOCKET_MODE:
            # Socket Mode with enhanced debugging info
            logger.info("Starting Slack app in Socket Mode with verbose debugging")
            print("\n" + "*"*80)
            print("STARTING IN SOCKET MODE - DIALOGFLOW RESPONSES WILL BE PRINTED TO CONSOLE")
            print("*"*80 + "\n")
            handler = SocketModeHandler(app, Config.SLACK_APP_TOKEN)
            handler.start()
        else:
            logger.info(f"Starting Slack app in HTTP mode on port {Config.PORT}")
            try:
                from flask import Flask, request, jsonify, redirect, render_template
                from slack_bolt.adapter.flask import SlackRequestHandler
                from slack_installer import create_install_button_html
                from slack_oauth_handler import process_slack_oauth, store_installation
            except ImportError:
                logger.error("Flask is required for HTTP mode. Please install it with: pip install flask")
                raise

            # Fix the template folder path - use absolute path
            template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
            logger.info(f"Using template directory: {template_dir}")
            
            flask_app = Flask(__name__, template_folder=template_dir)
            handler = SlackRequestHandler(app)
            
            @flask_app.route("/slack/events", methods=["POST"])
            def slack_events():
                """Handle Slack events with direct processing"""
                # Log the incoming request
                logger.info(f"Slack event received: {request.path}")
                
                # Handle challenge verification first
                if request.json and "challenge" in request.json:
                    challenge = request.json["challenge"]
                    logger.info(f"Responding to Slack challenge: {challenge}")
                    return jsonify({"challenge": challenge})
                
                # Get the entire event payload
                event_data = request.get_json()
                if not event_data:
                    logger.error("Empty event data received")
                    return jsonify({"status": "error", "message": "Empty event data"}), 200
                    
                # Extract key information
                event_id = event_data.get("event_id", "unknown")
                event_type = event_data.get("type")
                team_id = event_data.get("team_id")
                
                # Check if this is a retry - Slack retries can cause duplicate processing
                retry_num = request.headers.get("X-Slack-Retry-Num")
                retry_reason = request.headers.get("X-Slack-Retry-Reason")
                
                if retry_num:
                    logger.warning(f"Received a retry (#{retry_num}) from Slack. Reason: {retry_reason}")
                    # Acknowledge the retry but don't process it again
                    return jsonify({"status": "ok", "message": "Retry acknowledged"}), 200
                
                # Check if this is an event we've already seen
                if message_cache.contains(f"event_id:{event_id}"):
                    logger.warning(f"Duplicate event ID: {event_id} - already processed")
                    return jsonify({"status": "ok", "message": "Duplicate event"}), 200
                
                # Add this event ID to our cache
                message_cache.put(f"event_id:{event_id}")
                
                # Log detailed information about the event
                logger.info(f"Processing new event - ID: {event_id}, Type: {event_type}, Team: {team_id}")
                
                # Special handling for message events to avoid duplicate processing
                if event_type == "event_callback":
                    inner_event = event_data.get("event", {})
                    inner_type = inner_event.get("type")
                    
                    if inner_type == "message":
                        # Extract message details
                        ts = inner_event.get("ts")
                        channel = inner_event.get("channel")
                        user = inner_event.get("user")
                        text = inner_event.get("text", "")
                        subtype = inner_event.get("subtype")
                        channel_type = inner_event.get("channel_type")
                        
                        # Enhanced debugging
                        logger.debug(f"Message details - Channel: {channel} ({channel_type}), User: {user}, Text: '{text[:50]}{'...' if len(text) > 50 else ''}', Subtype: {subtype}")
                        
                        # Create a unique fingerprint for this message
                        msg_key = f"msg:{channel}:{user}:{ts}"
                        
                        # Skip any message subtypes
                        if subtype is not None:
                            logger.info(f"Skipping message with subtype: {subtype}")
                            return jsonify({"status": "ok", "message": "Subtype ignored"}), 200
                            
                        # Check if we've already processed this exact message
                        if message_cache.contains(msg_key):
                            logger.warning(f"Duplicate message detected with ts: {ts}")
                            return jsonify({"status": "ok", "message": "Duplicate message"}), 200
                        
                        # Log whether this is a direct message or mention
                        if channel_type == "im":
                            logger.info(f"Processing direct message from user {user}")
                        elif BOT_USER_ID and f"<@{BOT_USER_ID}>" in text:
                            logger.info(f"Processing mention from user {user}")
                        else:
                            logger.debug(f"Message doesn't explicitly mention bot, but proceeding based on other criteria")
                            
                        # Add this message to our cache
                        message_cache.put(msg_key)
                        
                        # Log that we're processing a new message
                        logger.info(f"Processing new message: {msg_key}")
                
                # Process the event using the handler
                try:
                    result = handler.handle(request)
                    return result
                except Exception as e:
                    logger.error(f"Error handling Slack event: {str(e)}", exc_info=True)
                    # Always return 200 OK to prevent Slack from retrying
                    return jsonify({"status": "ok", "error": str(e)}), 200
            
            @flask_app.route("/", methods=["GET"])
            def health_check():
                return "Slack bot is running! Try <a href='/install'>installing the app</a>."
            
            @flask_app.route("/install", methods=["GET"])
            def install():
                """Landing page for installing the Slack app"""
                try:
                    logger.info("Install route accessed")
                    install_button = create_install_button_html()
                    logger.info(f"Generated install button HTML: {install_button[:50]}...")
                    return render_template('install.html', install_button=install_button)
                except Exception as e:
                    logger.error(f"Error rendering install page: {str(e)}", exc_info=True)
                    return f"Error: {str(e)}", 500
            
            # Add a debugging route to list available templates
            @flask_app.route("/debug/templates", methods=["GET"])
            def list_templates():
                """List available templates for debugging"""
                try:
                    import os
                    templates = []
                    if os.path.exists(template_dir):
                        templates = os.listdir(template_dir)
                    return jsonify({
                        "template_dir": template_dir,
                        "exists": os.path.exists(template_dir),
                        "templates": templates
                    })
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            
            @flask_app.route("/slack/oauth_redirect", methods=["GET"])
            def slack_oauth_callback():
                """Handle OAuth callback from Slack app installation"""
                try:
                    code = request.args.get('code')
                    if not code:
                        logger.error("Missing code parameter in OAuth callback")
                        return redirect("/error?message=Missing_code_parameter")
                    
                    # Process the OAuth callback to get installation data
                    logger.info(f"Processing OAuth code: {code[:5]}...")
                    installation_data = process_slack_oauth(code)
                    if not installation_data:
                        logger.error("OAuth process failed")
                        return redirect("/error?message=OAuth_error")
                    
                    # Log the installation data structure (for debugging)
                    logger.debug(f"Installation data keys: {list(installation_data.keys())}")
                    
                    # Store the installation data in Firestore
                    success = store_installation(installation_data)
                    if not success:
                        logger.error("Failed to store installation")
                        return redirect("/error?message=Installation_storage_error")
                    
                    # Redirect to success page
                    logger.info("OAuth flow completed successfully")
                    return redirect("/success")
                
                except Exception as e:
                    logger.error(f"Error in OAuth callback: {str(e)}", exc_info=True)
                    return redirect("/error?message=Unexpected_error")
            
            # Add a success page route
            @flask_app.route("/success", methods=["GET"])
            def success():
                """Show success page after OAuth installation"""
                return render_template('success.html')
            
            # Add an error page route
            @flask_app.route("/error", methods=["GET"])
            def error():
                """Show error page with message"""
                message = request.args.get("message", "Unknown error")
                return render_template('error.html', error_message=message)
            
            @flask_app.route("/auth/check_login", methods=["GET"])
            def check_login():
                """Handle login check and redirect"""
                try:
                    state = request.args.get('state')
                    client_id = request.args.get('client_id')
                    redirect_after_login = request.args.get('redirect_after_login')
                    
                    if not all([state, client_id, redirect_after_login]):
                        return redirect("/error?message=Missing_parameters")
                    
                    # Check for existing session cookie
                    if request.cookies.get('dealmaker_session'):
                        # User is logged in, redirect to authorization
                        return redirect(f"{redirect_after_login}?" 
                            f"client_id={client_id}&" 
                            f"state={state}&" 
                            f"response_type=code&" 
                            f"scope={Config.OAUTH_SCOPE}")
                    
                    # User needs to log in first
                    login_url = (f"{Config.DEALMAKER_BASE_URL}/login?" 
                        f"return_to={urllib.parse.quote(redirect_after_login)}&" 
                        f"state={state}&" 
                        f"client_id={client_id}")
                    
                    return redirect(login_url)
                    
                except Exception as e:
                    logger.error(f"Error in login check: {str(e)}", exc_info=True)
                    return redirect("/error?message=Login_check_error")
                
            logger.info(f"Starting Flask app with routes: {[rule.rule for rule in flask_app.url_map.iter_rules()]}")
            flask_app.run(host="0.0.0.0", port=Config.PORT)
            
    except Exception as e:
        logger.error(f"Failed to start app: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    start_app()
