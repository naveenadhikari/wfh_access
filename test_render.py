from app import app
from flask import render_template
import json
with app.test_request_context('/'):
    try:
        render_template("add_user.html", role_templates=[], role_templates_json="{}", global_regions={"ap-south-1": {"securityGrpIds": ["sg-1"]}})
        print("add_user.html OK")
    except Exception as e:
        print(f"add_user.html Error: {e}")
    
    try:
        render_template("edit_user.html", username="test", user={"overRiddenRegionAndCfg":{}}, global_regions={"ap-south-1": {"securityGrpIds": ["sg-1"]}})
        print("edit_user.html OK")
    except Exception as e:
        print(f"edit_user.html Error: {e}")

    try:
        render_template("users.html", users={"test": {}}, ssh_key_status={"test": {"has_key": False}})
        print("users.html OK")
    except Exception as e:
        print(f"users.html Error: {e}")
