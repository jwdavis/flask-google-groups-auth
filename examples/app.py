import logging
import sys

from dotenv import load_dotenv
from flask import Flask, render_template_string

from flask_google_groups_auth import Config, require_auth, require_group_member
from flask_google_groups_auth.auth import get_current_user, setup_auth_routes

# Load environment variables from .env file (for local development)
load_dotenv()

app = Flask(__name__)

# Configure logging for Cloud Run
# Cloud Run captures logs from stdout/stderr, so we need to ensure logs go there
if not app.debug:
    # Production logging for Cloud Run
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
else:
    # Development logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout,
        force=True
    )

# Ensure all logs go to stdout (Cloud Run requirement)
for handler in app.logger.handlers:
    handler.setStream(sys.stdout)

app.logger.info("Flask app starting up...")

# Initialize the flask_google_groups_auth module
config = Config(app)

# Setup authentication routes
setup_auth_routes(app)


# ============================================================================
# OPTION 1: Specify a single custom group
# ============================================================================

@app.route('/admins-only')
@require_group_member('admins@example.com')
def admins_only_route():
    """
    This route is accessible only to users in the admins group.
    Single group as a string.
    """
    user = get_current_user()
    return f"<h1>Admins Only</h1><p>Welcome {user['name']}! You're an admin.</p>"


# ============================================================================
# OPTION 2: Specify custom groups as a list
# ============================================================================

@app.route('/editors')
@require_group_member(['editors@example.com', 'senior-editors@example.com'])
def editors_route():
    """
    This route is accessible to users in the editors OR senior-editors groups.
    Multiple groups - user needs to be in at least one.
    """
    user = get_current_user()
    return f"<h1>Editors Area</h1><p>Welcome {user['name']}! You're an editor or senior editor.</p>"


# ============================================================================
# OPTION 3: Multiple groups for different access levels
# ============================================================================

@app.route('/reports')
@require_group_member(['managers@example.com', 'analysts@example.com', 'admins@example.com'])
def reports_route():
    """
    This route is accessible to managers, analysts, OR admins.
    Demonstrates OR logic across multiple groups.
    """
    user = get_current_user()
    return f"<h1>Reports</h1><p>Welcome {user['name']}! You have access to view reports.</p>"


# ============================================================================
# OPTION 4: Department-specific access
# ============================================================================

@app.route('/engineering')
@require_group_member(['engineering@example.com', 'engineering-leads@example.com'])
def engineering_route():
    """
    This route is accessible to engineering team members or leads.
    """
    user = get_current_user()
    return f"<h1>Engineering Dashboard</h1><p>Welcome {user['name']}!</p>"


@app.route('/marketing')
@require_group_member(['marketing@example.com', 'marketing-leads@example.com'])
def marketing_route():
    """
    This route is accessible to marketing team members or leads.
    """
    user = get_current_user()
    return f"<h1>Marketing Dashboard</h1><p>Welcome {user['name']}!</p>"


# ============================================================================
# Public routes
# ============================================================================

@app.route('/')
def home():
    """Public home page."""
    app.logger.info("Home route accessed")
    user = get_current_user()
    app.logger.info(f"Current user: {user['email'] if user else 'Not logged in'}")
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Multi-Group Example</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
            .user-info { background: #f0f0f0; padding: 10px; border-radius: 5px; }
            .routes { margin-top: 20px; }
            .route { margin: 10px 0; padding: 10px; background: #e8f4f8; border-radius: 3px; }
            a { color: #0066cc; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Multi-Group Authorization Example</h1>
        
        {% if user %}
        <div class="user-info">
            <p><strong>Logged in as:</strong> {{ user.name }} ({{ user.email }})</p>
            <p><a href="/auth/logout">Logout</a></p>
        </div>
        {% else %}
        <div class="user-info">
            <p>Not logged in. <a href="/auth/login">Login with Google</a></p>
        </div>
        {% endif %}
        
        <div class="routes">
            <h2>Available Routes:</h2>
            
            <div class="route">
                <h3><a href="/admins-only">/admins-only</a></h3>
                <p>Accessible only to admins</p>
                <code>@require_group_member('admins@example.com')</code>
            </div>
            
            <div class="route">
                <h3><a href="/editors">/editors</a></h3>
                <p>Accessible to editors OR senior-editors</p>
                <code>@require_group_member(['editors@example.com', 'senior-editors@example.com'])</code>
            </div>
            
            <div class="route">
                <h3><a href="/reports">/reports</a></h3>
                <p>Accessible to managers, analysts, OR admins</p>
                <code>@require_group_member(['managers@example.com', 'analysts@example.com', 'admins@example.com'])</code>
            </div>
            
            <div class="route">
                <h3><a href="/engineering">/engineering</a></h3>
                <p>Accessible to engineering team or leads</p>
                <code>@require_group_member(['engineering@example.com', 'engineering-leads@example.com'])</code>
            </div>
            
            <div class="route">
                <h3><a href="/marketing">/marketing</a></h3>
                <p>Accessible to marketing team or leads</p>
                <code>@require_group_member(['marketing@example.com', 'marketing-leads@example.com'])</code>
            </div>
        </div>
        
        <h2>How It Works:</h2>
        <ul>
            <li>Users need to be in <strong>at least ONE</strong> of the specified groups (OR logic)</li>
            <li>Groups must always be passed directly to the decorator</li>
            <li>Single group: <code>@require_group_member('group@example.com')</code></li>
            <li>Multiple groups: <code>@require_group_member(['group1@example.com', 'group2@example.com'])</code></li>
        </ul>
    </body>
    </html>
    """
    
    return render_template_string(template, user=user)


if __name__ == '__main__':
    app.run(debug=True, port=8080)
