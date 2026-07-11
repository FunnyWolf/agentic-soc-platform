import logging


logger = logging.getLogger(__name__)


def ldap_escape_filter_value(value):
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def ldap_authenticates(username, password, config=None):
    if config is None:
        from apps.settings.runtime_config import get_ldap_config

        config = get_ldap_config()

    if not config.get("enabled"):
        logger.warning("LDAP login failed for %s: LDAP login is disabled", username)
        return False

    server_uri = (config.get("server_uri") or "").strip()
    if not server_uri:
        logger.warning("LDAP login failed for %s: LDAP server URI is empty", username)
        return False

    try:
        from ldap3 import SUBTREE, Connection, Server
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:
        logger.warning("LDAP login failed for %s: ldap3 is not installed", username, exc_info=exc)
        return False

    connections = []
    stage = "initializing"
    try:
        logger.info("LDAP login started for %s using server %s", username, server_uri)
        server = Server(server_uri)
        search_base = (config.get("user_search_base_dn") or "").strip()

        if search_base:
            stage = "service bind"
            bind_dn = (config.get("bind_dn") or "").strip()
            bind_kwargs = {}
            if bind_dn:
                bind_kwargs = {"user": bind_dn, "password": config.get("bind_password") or ""}
            login_attr = (config.get("user_login_attr") or "").strip() or "uid"
            logger.info(
                "LDAP search-bind mode for %s: base_dn=%s login_attr=%s bind_dn_configured=%s bind_password_configured=%s",
                username,
                search_base,
                login_attr,
                bool(bind_dn),
                bool(config.get("bind_password")),
            )
            conn = Connection(server, auto_bind=True, **bind_kwargs)
            connections.append(conn)
            escaped_username = ldap_escape_filter_value(username)
            stage = "user search"
            logger.info(
                "LDAP searching user for %s: base_dn=%s filter=(%s=%s)",
                username,
                search_base,
                login_attr,
                escaped_username,
            )
            found = conn.search(
                search_base,
                f"({login_attr}={escaped_username})",
                search_scope=SUBTREE,
                attributes=[],
            )
            if not found or not conn.entries:
                logger.warning(
                    "LDAP login failed for %s: no user found under %s with %s=%s",
                    username,
                    search_base,
                    login_attr,
                    escaped_username,
                )
                return False
            user_dn = conn.entries[0].entry_dn
            logger.info("LDAP found user DN for %s: %s", username, user_dn)
        else:
            domain = (config.get("domain") or "").strip()
            user_dn = f"{username}@{domain}" if domain else username
            logger.info(
                "LDAP direct-bind mode for %s: domain_configured=%s bind_user=%s",
                username,
                bool(domain),
                user_dn,
            )

        stage = "user bind"
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        connections.append(user_conn)
        logger.info("LDAP login succeeded for %s", username)
        return True
    except LDAPException as exc:
        logger.warning(
            "LDAP login failed for %s during %s: %s",
            username,
            stage,
            exc,
            exc_info=exc,
        )
        return False
    except Exception as exc:
        logger.warning(
            "LDAP login failed for %s during %s due to unexpected error: %s",
            username,
            stage,
            exc,
            exc_info=exc,
        )
        return False
    finally:
        for conn in connections:
            try:
                conn.unbind()
            except LDAPException:
                pass


def test_ldap_config(config, *, test_username="", test_password=""):
    if not config.get("enabled"):
        return {"success": False, "detail": "LDAP login is disabled.", "response_preview": ""}
    if not (config.get("server_uri") or "").strip():
        return {"success": False, "detail": "LDAP server URI is required.", "response_preview": ""}

    if test_username or test_password:
        if not test_username or not test_password:
            return {"success": False, "detail": "Both test username and test password are required.", "response_preview": ""}
        success = ldap_authenticates(test_username, test_password, config=config)
        return {
            "success": success,
            "detail": "LDAP test user authenticated successfully." if success else "LDAP test user authentication failed.",
            "response_preview": "",
        }

    try:
        from ldap3 import Connection, Server
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:
        return {"success": False, "detail": f"ldap3 is not installed: {exc}", "response_preview": ""}

    try:
        server = Server(config["server_uri"])
        bind_dn = (config.get("bind_dn") or "").strip()
        bind_kwargs = {}
        if bind_dn:
            bind_kwargs = {"user": bind_dn, "password": config.get("bind_password") or ""}
        conn = Connection(server, auto_bind=True, **bind_kwargs)
        conn.unbind()
        return {"success": True, "detail": "LDAP bind succeeded.", "response_preview": ""}
    except LDAPException as exc:
        return {"success": False, "detail": f"LDAP bind failed: {exc}", "response_preview": ""}
