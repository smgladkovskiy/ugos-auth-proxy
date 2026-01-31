"""
authentik Expression Policy: ugos-password-validation-policy

This policy handles UGOS user authentication and auto-provisioning.
Copy this code to authentik: Customization -> Policies -> Create -> Expression Policy

Bind to `ugos-password-deny-stage` with negate=True
"""

import requests
from authentik.core.models import User, Group

# ========== Configuration ==========
# Change these values to match your environment
UGOS_AUTH_PROXY_URL = "http://192.168.0.40:8180"  # Your ugos-auth-proxy address
USER_PATH = "ugos"                                 # Path for auto-provisioned users
DEFAULT_EMAIL_DOMAIN = "example.com"               # Default email domain
UGOS_USERS_GROUP = "UGOS Users"                    # Group for all UGOS users

# UGOS group -> authentik group mapping
GROUP_MAP = {
    "admin": "admins",
    "family": "family",
}

# ========== Get password from prompt_data ==========
password = request.context.get("prompt_data", {}).get("password")
if not password:
    ak_message("Password is required")
    return False

# ========== Get pending_user from context ==========
pending_user = request.context.get("pending_user")
if not pending_user:
    ak_message("User identification failed")
    return False

username = pending_user.username

# ========== Check if user is real (has pk) or fake (pretend_user_exists) ==========
user_is_fake = pending_user.pk is None

if user_is_fake:
    # User doesn't exist in authentik - need to validate via UGOS and create

    # ========== Validate via UGOS Auth Proxy ==========
    try:
        validate_resp = requests.post(
            f"{UGOS_AUTH_PROXY_URL}/validate",
            json={"username": username, "password": password},
            timeout=5,
        )
        validate_result = validate_resp.json()

        if not validate_result.get("valid", False):
            ak_message("Invalid password")
            return False
    except Exception as e:
        ak_message(f"Authentication service unavailable: {str(e)}")
        return False

    # ========== Get user info from UGOS ==========
    try:
        info_resp = requests.get(
            f"{UGOS_AUTH_PROXY_URL}/user-info",
            params={"username": username},
            timeout=5,
        )
        user_info = info_resp.json()

        if not user_info.get("exists", False):
            ak_message("User does not exist in UGOS")
            return False
    except Exception as e:
        ak_message(f"Failed to get user info: {str(e)}")
        return False

    # ========== Create user in authentik ==========
    try:
        full_name = user_info.get("full_name", username)
        if not full_name or full_name == username or full_name == "UGREEN USER":
            full_name = username.replace(".", " ").replace("_", " ").title()

        email = user_info.get("email", "")
        if not email:
            email = f"{username}@{DEFAULT_EMAIL_DOMAIN}"

        real_user = User.objects.create(
            username=username,
            name=full_name,
            email=email,
            path=USER_PATH,
            attributes={
                "ugos_user": True,
                "ugos_uid": user_info.get("uid"),
                "ugos_gid": user_info.get("gid"),
                "ugos_groups": user_info.get("groups", []),
                "ugos_home": user_info.get("home"),
                "auto_provisioned": True,
            },
        )

        # Add to UGOS Users group
        ugos_group, _ = Group.objects.get_or_create(name=UGOS_USERS_GROUP)
        real_user.ak_groups.add(ugos_group)

        # Map UGOS groups to authentik groups
        ugos_groups = user_info.get("groups", [])
        for ugos_grp, ak_grp in GROUP_MAP.items():
            if ugos_grp in ugos_groups:
                try:
                    mapped_group = Group.objects.get(name=ak_grp)
                    real_user.ak_groups.add(mapped_group)
                except Group.DoesNotExist:
                    pass

        real_user.save()

        # ========== Update flow context with real user ==========
        request.context["pending_user"] = real_user

        # Update flow_plan context directly (required for UserLoginStage)
        flow_plan = request.context.get("flow_plan")
        if flow_plan and hasattr(flow_plan, "context"):
            flow_plan.context["pending_user"] = real_user

    except Exception as e:
        ak_message(f"Failed to create user: {str(e)}")
        return False

    return True

else:
    # User exists - check if UGOS user or local
    is_ugos_user = pending_user.attributes.get("ugos_user", False)

    if not is_ugos_user:
        # Local user - check authentik password
        if pending_user.check_password(password):
            return True
        else:
            ak_message("Invalid password")
            return False

    # UGOS user - validate via UGOS Auth Proxy
    try:
        response = requests.post(
            f"{UGOS_AUTH_PROXY_URL}/validate",
            json={"username": username, "password": password},
            timeout=5,
        )
        result = response.json()

        if result.get("valid", False):
            return True
        else:
            ak_message("Invalid password")
            return False
    except Exception as e:
        ak_message(f"Authentication service error: {str(e)}")
        return False
