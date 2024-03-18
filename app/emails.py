import re

_simple_domain_re = r"[\w0-9-]+\.[\w0-9-.]+"
_simple_user_re = r"[\w0-9_.+-]+"


class InvalidEmailError(ValueError):
    def __init__(self, error_message: str) -> None:
        super().__init__(error_message)
        self.error_message = error_message


def check_email_format(email: str) -> str | None:
    """
    Check if an email address is avlid by returning a string
    with an error message or None if the email is valid.
    """

    email = email.strip()
    if not email:
        return "Email is empty"

    at_count = len([c for c in email if c == "@"])

    if at_count == 0:
        return "Email is missing @ symbol"

    if at_count > 1:
        return "Email has too man @ symbols"

    user, domain = email.split("@")

    if not user:
        return "Empty user"

    if not domain:
        return "Empty domain"

    if not re.match(_simple_domain_re, domain):
        return f"Invalid domain: {domain}"

    if not re.match(_simple_user_re, user):
        return f"Invalid user: {user}"

    return None


def validate_email(email: str) -> str:
    error = check_email_format(email)
    if error:
        raise InvalidEmailError(error)
    return email
