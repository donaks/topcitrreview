import hashlib
import hmac
import os
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from flask import current_app
from sqlalchemy.exc import IntegrityError


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def digest(user_id, code):
    key = current_app.secret_key.encode()
    return hmac.new(key, f"{user_id}:{code}".encode(), hashlib.sha256).hexdigest()


def send_code(email, code):
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = email
    message["Subject"] = "Your TOPCIT ReviewBank verification code"
    message.set_content(f"Enter {code} to verify your first student sign-in. "
                        "This code expires in 10 minutes.")
    port = int(os.getenv("SMTP_PORT", "587"))
    client = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    context = ssl.create_default_context()
    options = {"context": context} if port == 465 else {}
    with client(os.environ["SMTP_HOST"], port, timeout=10, **options) as smtp:
        if port != 465:
            smtp.starttls(context=context)
        if os.getenv("SMTP_USERNAME"):
            smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        smtp.send_message(message)


def issue_code(db, model, user):
    row = db.session.get(model, user.id)
    if row is None:
        db.session.add(model(user_id=user.id))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
    now = utc_now()
    code = f"{secrets.randbelow(1000000):06d}"
    signature = digest(user.id, code)
    available = model.query.filter(
        model.user_id == user.id, model.verified_at.is_(None),
        (model.sent_at.is_(None)) | (model.sent_at <= now - timedelta(minutes=1)),
        (model.attempts < 5) | (model.expires_at <= now))
    if not available.update(dict(signature=signature, sent_at=now,
                                 expires_at=now + timedelta(minutes=10), attempts=0),
                            synchronize_session=False):
        db.session.rollback()
        return "Use the latest code. You can resend after one minute, or after expiry if you used all five attempts."
    db.session.commit()
    try:
        send_code(user.email, code)
    except (OSError, KeyError, ValueError, smtplib.SMTPException):
        current_app.logger.error("Verification email delivery failed. Check the SMTP configuration.")
        model.query.filter_by(user_id=user.id, signature=signature).update(dict(signature=None))
        db.session.commit()
        return "Email delivery failed. Try sending another code in one minute."
    return "Check your email for your six-digit verification code."


def accept_code(db, model, user_id, code):
    now = utc_now()
    active = model.query.filter(model.user_id == user_id, model.verified_at.is_(None),
                                model.signature.isnot(None), model.expires_at > now,
                                model.attempts < 5)
    signature = digest(user_id, code)
    accepted = active.filter(model.signature == signature).update(
        dict(verified_at=now, signature=None), synchronize_session=False)
    if not accepted:
        active.filter(model.signature != signature).update(
            dict(attempts=model.attempts + 1), synchronize_session=False)
    db.session.commit()
    return bool(accepted)
