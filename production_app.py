"""
Production-ready Slack app that implements threading and best practices.
This version is optimized for reliability and performance.
"""

import os
import re
import json
import time
import logging
import hashlib
import threading
import signal
from collections import OrderedDict
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from config import Config
from logger_setup import logger
from dialogflow_client import DialogflowClient
from metrics import metrics
from firestore_client import FirestoreClient
from slack_bolt.authorization import AuthorizeResult

# Set up thread pool for concurrent message processing
from concurrent.futures import ThreadPoolExecutor

# Thread pool for handling message processing
message_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="slack_msg_worker")

# Rate limiting settings
MAX_REQUESTS_PER_MINUTE = 60  # Slack API rate limit
RATE_LIMIT_WINDOW = 60  # seconds

# Initialize metrics for tracking performance
total_processed = 0
total_errors = 0
start_time = time.time()
metrics_lock = threading.Lock()

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

# Initialize the Slack app with proper error handling
def init_slack_app():
    try:
        app = App(
            token=Config.SLACK_BOT_TOKEN,
            signing_secret=Config.SLACK_SIGNING_SECRET,
            authorize=authorize,
            process_before_response=True
        )
        logger.info("Slack app initialized successfully")
        return app
    except Exception as e:
        logger.critical(f"Failed to initialize Slack app: {str(e)}", exc_info=True)
        raise

# App instance
app = init_slack_app()

# Initialize Dialogflow client
dialogflow_client = DialogflowClient()

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
message_cache = LRUCache(capacity=5000)
mention_cache = LRUCache(capacity=1000)
event_id_cache = LRUCache(capacity=10000)  # For tracking processed event IDs

# Store the bot ID globally with thread safety
bot_user_id_lock = threading.Lock()
BOT_USER_ID = None

def get_bot_user_id(client):
    """Get the bot's user ID with caching and thread safety"""
    global BOT_USER_ID
    
    with bot_user_id_lock:
        if BOT_USER_ID is not None:
            return BOT_USER_ID
            
        try:
            auth_result = client.auth_test()
            if auth_result["ok"]:
                BOT_USER_ID = auth_result["user_id"]
                logger.info(f"Retrieved bot user ID: {BOT_USER_ID}")
                return BOT_USER_ID
            else:
                logger.error(f"Failed to get bot user ID: {auth_result.get('error')}")
                return None
        except Exception as e:
            logger.error(f"Error getting bot user ID: {str(e)}", exc_info=True)
            return None

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
        logger.warning(f"Duplicate message detected")
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
    """Handle message events from Slack with threading"""
    # Get the bot ID if we don't have it yet
    bot_user_id = get_bot_user_id(client)
    if not bot_user_id:
        logger.error("Could not determine bot user ID, skipping message processing")
        return
    
    # Extract the message
    event = body.get("event", {})
    event_id = body.get("event_id", "unknown")
    
    # Early check for duplicates based on event_id
    if event_id_cache.contains(f"event:{event_id}"):
        logger.warning(f"Duplicate event ID detected: {event_id}")
        return
    
    # Add event_id to cache to prevent duplicate processing
    event_id_cache.put(f"event:{event_id}")
    
    # Check if this is a message we should respond to
    if should_process_message(event, bot_user_id):
        # Submit the task to the thread pool
        message_executor.submit(
            process_and_respond_to_message_safe, 
            event, 
            client, 
            bot_user_id,
            event_id
        )
    else:
        logger.debug(f"Not processing message event: {event_id}")

@app.event("app_mention")
def handle_app_mention(body, logger, client, context):
    """Handle app mention events with threading"""
    # Get the bot ID if we don't have it yet
    bot_user_id = get_bot_user_id(client)
    if not bot_user_id:
        logger.error("Could not determine bot user ID, skipping mention processing")
        return
    
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
    if mention_cache.contains(fingerprint) or event_id_cache.contains(f"event:{event_id}"):
        logger.warning(f"Duplicate app_mention detected: {event_id}")
        return
        
    # Add to cache
    mention_cache.put(fingerprint)
    event_id_cache.put(f"event:{event_id}")
    
    # Make sure the mention is not from our bot
    if event.get("user") == bot_user_id:
        logger.debug("Ignoring self-mention")
        return
        
    # Submit the task to the thread pool
    message_executor.submit(
        process_and_respond_to_message_safe, 
        event, 
        client, 
        bot_user_id,
        event_id
    )

def process_and_respond_to_message_safe(event, client, bot_user_id, event_id):
    """Thread-safe wrapper for message processing with error handling and metrics"""
    global total_processed, total_errors
    
    try:
        # This runs in a separate thread from the thread pool
        logger.info(f"Processing event {event_id} in thread: {threading.current_thread().name}")
        
        # Execute the actual processing
        process_and_respond_to_message(event, client, bot_user_id)
        
        # Increment successful count
        with metrics_lock:
            total_processed += 1
            
    except Exception as e:
        # Increment error count
        with metrics_lock:
            total_errors += 1
            
        logger.error(f"Error in thread processing message: {str(e)}", exc_info=True)
        
        # Try to send an error message to the user
        try:
            channel_id = event.get("channel")
            thread_ts = event.get("thread_ts", event.get("ts"))
            
            if channel_id and thread_ts:
                client.chat_postMessage(
                    channel=channel_id,
                    text="I'm sorry, I encountered an error while processing your request.",
                    thread_ts=thread_ts
                )
                logger.info(f"Sent error response to user in channel {channel_id}, thread {thread_ts}")
        except Exception as notify_error:
            logger.error(f"Failed to send error notification: {str(notify_error)}")

def process_and_respond_to_message(event, client, bot_user_id):
    """Process the message and respond with Dialogflow, maintaining thread context"""
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
    if Config.USE_SOCKET_MODE and Config.PRINT_DIALOGFLOW_RESPONSES:
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
    if Config.USE_SOCKET_MODE and Config.PRINT_DIALOGFLOW_RESPONSES:
        print("\n" + "-"*40)
        print("SENDING TO SLACK:")
        print("-"*40)
        print(full_response)
        print("-"*40 + "\n")
    
    # Send the complete response directly to the user
    logger.info(f"Sending response to user {user_id} in channel {channel_id}")
    
    client.chat_postMessage(
        channel=channel_id,
        text=full_response,
        thread_ts=thread_ts  # Keep the conversation in the same thread
    )
    
    logger.info(f"Successfully responded to user {user_id} in thread {thread_ts}")

@app.command("/df_status")
def handle_status_command(ack, respond, command):
    """Handle command to check Dialogflow integration status with thread metrics"""
    ack()
    try:
        # Get metrics
        dialogflow_stats = metrics.get_metrics()
        
        # Calculate app metrics
        uptime = time.time() - start_time
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        with metrics_lock:
            local_total_processed = total_processed
            local_total_errors = total_errors
            
        error_rate = 0 if local_total_processed == 0 else (local_total_errors / local_total_processed) * 100
        
        # Respond with detailed status information
        response_text = (
            f"*Slack Bot Status Report*\n"
            f"• Uptime: {hours}h {minutes}m {seconds}s\n"
            f"• Active worker threads: {threading.active_count()}\n"
            f"• Messages processed: {local_total_processed}\n"
            f"• Processing errors: {local_total_errors} ({error_rate:.1f}%)\n\n"
            f"*Dialogflow Integration*\n"
            f"• API Calls: {dialogflow_stats['api_calls']}\n"
            f"• Successful: {dialogflow_stats['successful_calls']}\n"
            f"• Failed: {dialogflow_stats['failed_calls']}\n"
            f"• Average Response Time: {dialogflow_stats['avg_response_time']:.2f}s\n"
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
                # Run cleanup, get count of cleaned items
                count = cleanup_expired_sessions()
                logger.info(f"OAuth session cleanup complete - removed {count} expired sessions")
                # Run cleanup every 15 minutes
                time.sleep(900)
            except Exception as e:
                logger.error(f"Error in cleanup task: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying on error
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True, name="oauth-cleanup")
    cleanup_thread.start()
    logger.info("OAuth session cleanup task scheduled")

def shutdown_handler(signum, frame):
    """Handle graceful shutdown of the application"""
    logger.info(f"Received signal {signum}, shutting down...")
    
    # Log final metrics
    with metrics_lock:
        logger.info(f"Processed {total_processed} messages, with {total_errors} errors")
    
    # Shutdown the thread pool gracefully - wait for ongoing tasks to complete
    logger.info("Shutting down thread pool...")
    message_executor.shutdown(wait=True)
    
    # Now exit the process
    logger.info("Shutdown complete, exiting.")
    os._exit(0)

def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    logger.info("Signal handlers established for graceful shutdown")

def setup_http_server():
    """Setup HTTP server with Flask"""
    from flask import Flask, request, jsonify, redirect, render_template
    from slack_bolt.adapter.flask import SlackRequestHandler
    from slack_installer import create_install_button_html
    from slack_oauth_handler import process_slack_oauth, store_installation
    
    # Fix the template folder path - use absolute path
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
    logger.info(f"Using template directory: {template_dir}")
    
    flask_app = Flask(__name__, template_folder=template_dir)
    handler = SlackRequestHandler(app)
    
    @flask_app.route("/slack/events", methods=["POST"])
    def slack_events():
        """Handle Slack events with direct processing"""
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
        
        # Check if this is a retry - Slack retries can cause duplicate processing
        retry_num = request.headers.get("X-Slack-Retry-Num")
        if retry_num:
            logger.warning(f"Received a retry (#{retry_num}) from Slack")
            return jsonify({"status": "ok", "message": "Retry acknowledged"}), 200
        
        # Check if this is an event we've already seen
        if event_id_cache.contains(f"event_id:{event_id}"):
            logger.warning(f"Duplicate event ID: {event_id} - already processed")
            return jsonify({"status": "ok", "message": "Duplicate event"}), 200
        
        # Process the event using the handler
        try:
            result = handler.handle(request)
            return result
        except Exception as e:
            logger.error(f"Error handling Slack event: {str(e)}", exc_info=True)
            return jsonify({"status": "ok", "error": str(e)}), 200
    
    # Add more routes for OAuth, installation, etc.
    @flask_app.route("/", methods=["GET"])
    def health_check():
        return "Slack bot is running! Try <a href='/install'>installing the app</a>."
    
    @flask_app.route("/install", methods=["GET"])
    def install():
        """Landing page for installing the Slack app"""
        try:
            install_button = create_install_button_html()
            return render_template('install.html', install_button=install_button)
        except Exception as e:
            logger.error(f"Error rendering install page: {str(e)}", exc_info=True)
            return f"Error: {str(e)}", 500
            
    @flask_app.route("/slack/oauth_redirect", methods=["GET"])
    def slack_oauth_callback():
        """Handle OAuth callback from Slack app installation"""
        try:
            code = request.args.get('code')
            if not code:
                logger.error("Missing code parameter in OAuth callback")
                return redirect("/error?message=Missing_code_parameter")
            
            installation_data = process_slack_oauth(code)
            if not installation_data:
                logger.error("OAuth process failed")
                return redirect("/error?message=OAuth_error")
            
            success = store_installation(installation_data)
            if not success:
                logger.error("Failed to store installation")
                return redirect("/error?message=Installation_storage_error")
            
            logger.info("OAuth flow completed successfully")
            return redirect("/success")
        
        except Exception as e:
            logger.error(f"Error in OAuth callback: {str(e)}", exc_info=True)
            return redirect("/error?message=Unexpected_error")
    
    # Add more required routes...
    
    return flask_app

def start_app():
    """Start the Slack application"""
    try:
        # Validate config before starting
        Config.validate()
        print(f"Environment: {Config.ENVIRONMENT}")
        
        # Set up signal handlers for graceful shutdown
        setup_signal_handlers()
        
        # Start the session cleanup task
        schedule_session_cleanup()
        
        # Print startup banner
        print("\n" + "="*80)
        print("SLACK INTEGRATION STARTING")
        print(f"Environment: {Config.ENVIRONMENT}")
        print(f"Debug mode: {Config.ENABLE_VERBOSE_LOGGING}")
        print("="*80 + "\n")
        
        if Config.USE_SOCKET_MODE:
            # Socket Mode with enhanced debugging info
            logger.info("Starting Slack app in Socket Mode")
            handler = SocketModeHandler(app, Config.SLACK_APP_TOKEN)
            handler.start()
        else:
            # HTTP mode
            logger.info(f"Starting Slack app in HTTP mode on port {Config.PORT}")
            flask_app = setup_http_server()
            flask_app.run(host="0.0.0.0", port=Config.PORT)
            
    except ConfigError as e:
        print(f"Configuration error: {str(e)}")
        raise
    except Exception as e:
        print(f"Failed to start app: {str(e)}")
        raise

if __name__ == "__main__":
    start_app()
