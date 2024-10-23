from flask import Blueprint, Response, jsonify, request
from ..models import User, UserActiveStatusChange, RolesLookup, UsersRoles
from ..extensions import db
from ..services.user_service import create_user, check_password
import logging
import sys
import json
from http import HTTPStatus


# Configure logger to print to shell.
#   (move this to a separate file so it can be referenced by multiple modules)
logger = logging.getLogger("alembic.env")
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

user_bp = Blueprint("user_bp", __name__)


# Route to register a new user.
""" Register a user with username, email, and password. """


@user_bp.route("/register", methods=["POST"])
def register():
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/register -H "Content-Type: application/json"
        -d '{"username":"Dev Userson", "email":"dev.userson@example.com", "password":"sosecure"}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/register -Method POST -Headers @{"Content-Type" = "application/json"}
    -Body '{"username":"Dev Userson", "email":"dev.userson@example.com", "password":"sosecure"}'
    """
    # Add user authentication & session handling here.
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    # status = defaults to inactive
    # check to see if user already exists
    user = User.query.filter_by(email=email).first()
    if user is not None:
        logger.debug(f"\n{username} with {email} already exists.")
        return jsonify({"message": "User email already exists."}), HTTPStatus.CONFLICT
    user = User.query.filter_by(username=username).first()
    if user is not None:
        logger.debug(f"\n{username} already exists.")
        return jsonify({"message": "Username already exists."}), HTTPStatus.CONFLICT
    user = create_user(username, email, password)
    logger.debug(f"\n{username} with {email} created.")
    return (
        jsonify({f"message": "User " + username + " registered successfully"}),
        HTTPStatus.CREATED,
    )


# Route to log in a user.
""" Log a user in using email and password. """


@user_bp.route("/login", methods=["POST"])
def login():
    # Add user authentication & session handling here.
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json"
        -d '{"email":"dev.userson@example.com", "password":"sosecure"}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/login -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"email":"dev.userson@example.com", "password":"sosecure"}'
    """
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if check_password(email, password) is False:
        logger.debug(f"\nLogin failed: Invalid user/pw.")
        return (
            jsonify({"message": "Login failed: Invalid credentials"}),
            HTTPStatus.UNAUTHORIZED,
        )
    else:
        logger.debug(f"\nLogin successful.")
        return jsonify({"message": "Login successful", "email": email}), HTTPStatus.OK


# Route to show a user profile.
""" Show a user's info and their roles. Reads from the
    users, users_roles, and roles_lookup tables. """


@user_bp.route("/profile", methods=["POST"])
def profile():
    # Add user authentication & session handling here.
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/profile
        -H "Content-Type: application/json"
        -d '{"username":"Dev Useron", "email":""}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/profile -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"username":"Dev Userson", "email":""}'
    """
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    """ If email is not provided, use username to get user_id.
    If username is not provided, use email.
    If neither, return 400. """
    if (email is None or email == "") and (username is None or username == ""):
        logger.debug(f"\nEmail or username required.")
        return (
            jsonify({"message": "Email or username required."}),
            HTTPStatus.BAD_REQUEST,
        )
    elif email is None or email == "":
        user = User.query.filter_by(username=username).first()
    else:
        user = User.query.filter_by(email=email).first()
    if user is None:
        logger.debug(f"\nUser not found.")
        return jsonify({"message": "User not found."}), HTTPStatus.NOT_FOUND
    else:
        # Get user profile information.
        #   Get the roles and departments using the users_roles table
        # Add error handling here:
        roles_depts = (
            db.session.query(RolesLookup.role_name, RolesLookup.department_name)
            .join(UsersRoles, RolesLookup.id == UsersRoles.role_id)
            .filter(UsersRoles.user_id == user.id)
            .all()
        )
        roles_list = []
        for role_dept in roles_depts:
            roles_list.append(f"{role_dept[0]}/{role_dept[1]}")

        #   Build the user profile string
        profile = (
            f"\nUsername: {user.username}\n"
            f"email: {user.email}\n"
            f"active: {user.active}\n"
            f"roles: {str(roles_list)}\n"
        )
        logger.debug(profile)
        return jsonify({"message": "User profile information" + profile}), HTTPStatus.OK


# Route to hit to toggle active/inactive status of a user.
""" Route to toggle active/inactive status of a user.
    Modifies users and users_active_status_changes tables. """


@user_bp.route("/toggle-active", methods=["POST"])
def toggle_active():
    # Add user authentication & session handling here.
    """ POST looks like:
    curl -X POST http://127.0.0.1:5000/toggle-active \
        -H "Content-Type: application/json" \
        -d '{"email":"dev.userson@example.com"}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/toggle-active -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"email":"dev.userson@example.com"}'
    """
    data = request.get_json()
    email = data.get("email")
    user = User.query.filter_by(email=email).first()
    if user is None:
        logger.debug(f"\nUser email {email} not found.")
        return jsonify({"message": "User not found"}), HTTPStatus.NOT_FOUND
    else:
        user.active = not user.active
        # Save the status change to UserActiveStatusChange table.
        status_change = UserActiveStatusChange(
            id_user=user.id, status="active" if user.active else "inactive"
        )
        db.session.commit()
        logger.debug(f"\nUser {user.username} now {user.active}.")
        return (
            jsonify(
                {
                    "message": f"User "
                    + user.username
                    + " status toggled to "
                    + user.active
                }
            ),
            HTTPStatus.OK,
        )


# Route to show all users.
""" Deprecated in favor of access-report and users-roles routes.
    Show all users and their roles. Reads from the users table.
    Note: This was the method used before we added users_roles
    and roles_lookup tables. """


@user_bp.route("/users", methods=["GET"])
def users():
    # Add user authentication & session handling here.
    """GET looks like:
    curl -X GET http://127.0.0.1:5000/users
        -H "Content-Type: application/json"
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/users -Method GET -Headers @{"Content-Type" = "application/json"}
    """
    users = User.query.all()
    user_list = []
    logger.debug(f"\nUsers:")
    for user in users:
        user_list.append(
            {
                "user": user.username,
                "email": user.email,
                "role": user.access_level,
                "active": user.active,
            }
        )
        logger.debug(
            f"{user.username} | {user.email} | Active: {user.active} | Role: {user.access_level}"
        )
    response = json.dumps(user_list)
    return Response(response, mimetype="application/json"), HTTPStatus.OK


# Route to show all users.
""" Show all users and their roles. Reads from the users table. """


@user_bp.route("/access-report", methods=["POST"])
def access_report():
    # Add user authentication & session handling here.
    """(Note: can replace "all_users" below with "active_users" or "inactive_users")
    POST looks like:
    curl -X POST http://127.0.0.1:5000/access-report
        -H "Content-Type: application/json"
        -d '{"limit_to":"all_users"}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/access-report -Method POST
        -Headers @{"Content-Type" = "application/json"} -Body '{"limit_to":"all_users"}'
    """
    data = request.get_json()
    limit_to = data.get("limit_to")
    # limit_to may be "all_users", "active_users", or "inactive_users"
    if limit_to == "all_users":
        users = User.query.all()
    elif limit_to == "active_users":
        users = User.query.filter_by(active=True).all()
    elif limit_to == "inactive_users":
        users = User.query.filter_by(active=False).all()
    else:
        logger.debug(
            f"\nInvalid request: limit_to must be 'all_users', 'active_users', or 'inactive_users'."
        )
        return jsonify({"message": "Invalid request."}), HTTPStatus.BAD_REQUEST
    user_list = []
    logger.debug(f"\nUsers:")
    for user in users:
        active = "active" if user.active else "inactive"
        user_list.append(
            {
                "user": user.username,
                "email": user.email,
                "role": user.access_level,
                "active": active,
            }
        )
        logger.debug(f"{user.username} | {user.email} | {user.access_level} | {active}")
    response = json.dumps(user_list)
    return Response(response, mimetype="application/json"), HTTPStatus.OK


# Route to show all users and their roles.
""" Show all users and their roles. Reads from the
    users, users_roles, and roles_lookup tables. """


@user_bp.route("/users-roles", methods=["GET"])
def users_roles():
    # Add user authentication & session handling here.
    """GET looks like:
    curl -X GET http://127.0.0.1:5000/users-roles
        -H "Content-Type: application/json"
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/users-roles
        -Method GET -Headers @{"Content-Type" = "application/json"}
    """
    users = User.query.all()
    user_list = []
    logger.debug(f"\nUsers:")
    for user in users:
        id_user = user.id
        # For each user, get the roles and departments using the users_roles table.
        # Add error handling here:
        roles_depts = (
            db.session.query(RolesLookup.role_name, RolesLookup.department_name)
            .join(UsersRoles, RolesLookup.id == UsersRoles.role_id)
            .filter(UsersRoles.user_id == id_user)
            .all()
        )
        roles_list = []
        for role_dept in roles_depts:
            roles_list.append(f"{role_dept[0]}/{role_dept[1]}")

        user_list.append(
            {
                "user": user.username,
                "email": user.email,
                "roles": str(roles_list),
                "active": user.active,
            }
        )
        logger.debug(
            f"{user.username} | {user.email} | Active: {user.active} | Roles: {str(roles_list)}"
        )
    response = json.dumps(user_list)
    return Response(response, mimetype="application/json"), HTTPStatus.OK


# Route to delete a user.
""" Delete a user (using email address) and all references to
    that user in the UserActiveStatusChange table. """


@user_bp.route("/delete-user", methods=["POST"])
def delete_user():
    # Add user authentication & session handling here.
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/delete-user
        -H "Content-Type: application/json"
        -d '{"email":"dev.userson@example.com"}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/delete-user -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"email":"dev.userson@example.com"}'
    """
    data = request.get_json()
    email = data.get("email")
    user = User.query.filter_by(email=email).first()
    if user is None:
        logger.debug(f"User with email {email} not found.")
        return (
            jsonify({"message": "User with email " + email + " not found."}),
            HTTPStatus.NOT_FOUND,
        )
    else:
        # Delete references to user in UserActiveStatusChange table.
        status_changes = UserActiveStatusChange.query.filter_by(id_user=user.id).all()
        for status_change in status_changes:
            db.session.delete(status_change)
        # Now delete the user.
        db.session.delete(user)
        db.session.commit()
        logger.debug(f"\n{user.username} with {email} deleted")
        return (
            jsonify(
                {"message": "User " + user.username + " with " + email + " deleted"}
            ),
            HTTPStatus.OK,
        )


# Route to show all roles/depts.
""" Show all roles/depts from roles_lookup tables. """


@user_bp.route("/roles-show", methods=["GET"])
def roles_show():
    # Add user authentication & session handling here.
    """GET looks like:
    curl -X GET http://127.0.0.1:5000/roles-show
        -H "Content-Type: application/json"
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/roles-show
        -Method GET -Headers @{"Content-Type" = "application/json"}
    """
    # Get all roles from roles_lookup table.
    # Add error handling here:
    roles = RolesLookup.query.all()
    roles_list = []
    logger.debug(f"\nRoles:")
    for role in roles:
        roles_list.append(
            f"{role.role_name}/{role.department_name}"
        )  # Access attributes directly
        logger.debug(f"{role.role_name}/{role.department_name}")
    response = json.dumps(roles_list)
    return Response(response, mimetype="application/json"), HTTPStatus.OK


# Route to create roles.
""" Create role(s)/dept(s) in roles_lookup with
    attributes of role_name and department_name.
    Combination of role_name and department_name is unique. """


@user_bp.route("/create-roles", methods=["POST"])
def create_roles():
    # Add user authentication & session handling here.
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/create-roles
        -H "Content-Type: application/json"
        -d '{"roles_depts":["Senior Dev,Getting Started", "Dev,Getting Started"]}'
        OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/create-roles -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"role_dept":"Senior Dev,Getting Started", "role_dept":"Dev,Getting Started"}'
    """
    data = request.get_json()
    roles_depts = data.get("roles_depts")  # Expecting a list of roles and departments
    if not roles_depts:  # Check if roles_depts is empty
        return (
            jsonify({"message": "Missing Role(s)/Dept(s)."}),
            HTTPStatus.BAD_REQUEST,
        )  # missing arg.
    # Add format validation here.
    logger.debug(f"roles_depts={str(roles_depts)}")
    success_counter = 0
    success_message = "Role(s)/Dept(s) created."
    try:
        logger.debug(f"Creating Role(s)/Dept(s)...")
        for role_dept in roles_depts:
            parts = role_dept.split(",")
            # logger.debug(f"role_dept={str(role_dept)}")
            # Chose not to use tuple unpacking below, for clarity/debugging/scalability.
            role_name = parts[0]
            dept_name = parts[1]

            # Check if the Role/Dept combos exist in the database.
            role_dept_combo_exists = RolesLookup.query.filter_by(
                role_name=role_name, department_name=dept_name
            ).first()
            if role_dept_combo_exists is None:
                logger.debug(
                    f"Success: Role/Dept {role_name}/{dept_name} combination not present."
                )
                new_role = RolesLookup(role_name=role_name, department_name=dept_name)
                logger.debug(f"Role/Dept {role_name}/{dept_name} combination added.")
                db.session.add(new_role)
                db.session.commit()
                success_counter += 1
    except Exception as e:
        logger.debug(f"Error creating Role(s)/Dept(s): {str(e)}")
        return (
            jsonify({"message": "Error creating Role(s)/Dept(s)."}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    status = HTTPStatus.CREATED
    if success_counter == 0:
        status = HTTPStatus.BAD_REQUEST
        success_message = "Role(s)/Dept(s) not created."
    logger.debug(f"{success_message} {str(success_counter)} created.")
    return jsonify({"message": success_message}), status


# Route to assign roles to users.
""" Allow for a user to be assigned one or more roles.
    This will be done by adding record(s) to the users_roles table.
    Potential for this to receive a list of roles to assign to a user
    or a list of users (via email) to assign role(s) to. """


@user_bp.route("/assign-roles", methods=["POST"])
def assign_roles():
    # Add user authentication & session handling here.
    """POST looks like:
    curl -X POST http://127.0.0.1:5000/assign-roles
        -H "Content-Type: application/json"
        -d '{"emails_roles_depts":[
            "dev.userson@example.com,Senior Dev,Getting Started",
            "scott@oceanmedia.net,Dev,Getting Started", "scott@oceanmedia.net,Dev,Finance Dept"
            ]}'
    OR
    Invoke-WebRequest -Uri http://127.0.0.1:5000/assign-roles -Method POST -Headers @{"Content-Type" = "application/json"}
        -Body '{"emails_roles_depts":[
            "dev.userson@example.com,Senior Dev,Getting Started",
            "bozo@oceanmedia.net,Dev,Getting Started", "scotter@oceanmedia.net,Dev,Finance Dept"
            ]}'
    """
    data = request.get_json()
    emails_roles_depts = data.get("emails_roles_depts")
    logger.debug(f"\n")
    if not emails_roles_depts:
        logger.debug(f"Invalid input.")
        return jsonify({"message": "Invalid input."}), HTTPStatus.BAD_REQUEST

    success_counter = 0
    success_message = "Role(s)/Dept(s) assigned to user(s)."

    for email_role_dept in emails_roles_depts:
        parts = email_role_dept.split(",")
        if len(parts) != 3:
            logger.debug(f"Invalid argument item: {email_role_dept}.")
            success_message = f"Invalid argument item: {email_role_dept}."
            continue
        # Chose not to use tuple unpacking below, for clarity/debugging/scalability.
        # user_email, role_name, dept_name = parts
        user_email = parts[0]
        role_name = parts[1]
        dept_name = parts[2]

        # Check if the role/dept combo exists and if not, add to roles_lookup
        role_dept_combo_exists = RolesLookup.query.filter_by(
            role_name=role_name, department_name=dept_name
        ).first()
        if role_dept_combo_exists is None:
            new_role = RolesLookup(role_name=role_name, department_name=dept_name)
            db.session.add(new_role)
            db.session.commit()
            role_exists = new_role
            logger.debug(f"New role/dept {role_name}/{dept_name} added.")

        # Assign the role to the user
        user = User.query.filter_by(email=user_email).first()
        if user is None:
            logger.debug(f"User with email {user_email} not found.")
            success_message = f"User with email {user_email} not found."
            continue

        user_role_exists = UsersRoles.query.filter_by(
            user_id=user.id, role_id=role_exists.id
        ).first()
        if user_role_exists is None:
            user_role = UsersRoles(user_id=user.id, role_id=role_exists.id)
            db.session.add(user_role)
            success_counter += 1

    db.session.commit()
    logger.debug(f"Role(s) assigned.")
    status = HTTPStatus.OK
    if success_counter == 0:
        status = HTTPStatus.BAD_REQUEST
    else:
        success_message = (
            f"Successfully assigned {str(success_counter)} role(s)/dept(s)."
        )
    return jsonify({"message": success_message}), status
