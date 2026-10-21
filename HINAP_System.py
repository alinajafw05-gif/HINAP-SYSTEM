"""HINAP patient management, BMI screening, authentication and PDF reports.

For local development only. Do not use real patient data in an unprotected demo.
Set HINAP_SECRET_KEY before deployment and disable debug mode in production.
"""

import math
import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from html import escape
from io import BytesIO
from urllib.parse import urlsplit

import click
from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    send_file, session, url_for,
)
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)

database_url = os.environ.get("DATABASE_URL", "sqlite:///hinap.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config.update(
    SQLALCHEMY_DATABASE_URI=database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.environ.get("HINAP_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HINAP_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)
db = SQLAlchemy(app)


def utc_now():
    """Store naive UTC timestamps to match the existing SQLite database."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Upgraded recommendation column to db.Text to support advanced AI diet plans
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    bmi = db.Column(db.Float)
    bmi_status = db.Column(db.String(50))
    nutrition_status = db.Column(db.String(100))
    risk_level = db.Column(db.String(50))
    recommendation = db.Column(db.Text)
    assessment_date = db.Column(db.DateTime, default=utc_now)


class AssessmentHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"))
    date = db.Column(db.DateTime, default=utc_now)
    weight = db.Column(db.Float)
    bmi = db.Column(db.Float)
    bmi_status = db.Column(db.String(50))
    risk_level = db.Column(db.String(50))
    recommendation = db.Column(db.Text)


class User(db.Model):
    """Authorized account; passwords are stored as hashes, not plaintext."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="doctor")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_template_globals():
    return {"csrf_token": csrf_token, "current_user": getattr(g, "current_user", None)}


def is_safe_next_url(target):
    if not target:
        return False
    parsed = urlsplit(target)
    return (
        not parsed.scheme and not parsed.netloc
        and target.startswith("/") and not target.startswith("//")
    )


@app.before_request
def protect_requests():
    if request.method == "POST":
        supplied = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not supplied or not secrets.compare_digest(supplied, expected):
            abort(400, description="Missing or invalid security token. Reload the page and try again.")

    if request.endpoint in {"static", "login"}:
        return None

    user_id = session.get("user_id")
    if not user_id:
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=next_url))

    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        session.clear()
        flash("Your session has expired or your account is inactive. Please sign in again.", "error")
        return redirect(url_for("login"))

    g.current_user = user
    return None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is None or user.role != "admin":
            abort(403, description="Administrator access is required.")
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(
            db.func.lower(User.username) == username.lower()
        ).first() if username else None

        if user and user.is_active and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["_csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            flash("Signed in successfully.", "success")
            target = request.args.get("next", "")
            return redirect(target if is_safe_next_url(target) else url_for("home"))

        flash("Invalid username or password, or the account is inactive.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.cli.command("create-admin")
def create_admin_command():
    """Create the first administrator account from the terminal."""
    db.create_all()
    username = click.prompt("Choose an administrator username").strip()
    if not 3 <= len(username) <= 40:
        raise click.ClickException("Username must be between 3 and 40 characters.")
    exists = User.query.filter(db.func.lower(User.username) == username.lower()).first()
    if exists:
        raise click.ClickException("That username already exists.")
    password = click.prompt("Choose a password (at least 12 characters)", hide_input=True)
    confirmation = click.prompt("Confirm password", hide_input=True)
    if password != confirmation:
        raise click.ClickException("Passwords do not match.")
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters.")
    db.session.add(User(
        username=username,
        password_hash=generate_password_hash(password),
        role="admin",
        is_active=True,
    ))
    db.session.commit()
    click.echo(f"Administrator account '{username}' created successfully.")


def calculate_health(bmi, age, gender, weight, height_m):
    """Advanced clinical BMI screening and personalized AI nutrition & diet recommendation engine."""
    if age < 20:
        return (
            "Age-specific assessment", 
            "Not assessed using adult BMI", 
            "Not assessed",
            "Pediatric/Adolescent Note: Use age- and sex-specific growth charts with a qualified pediatrician. Ensure balanced nutrition rich in calcium and iron to support growth."
        )

    height_cm = height_m * 100.0
    base_bmr = (10 * weight) + (6.25 * height_cm) - (5 * age)
    if gender and gender.lower() == "female":
        bmr = base_bmr - 161
    else:
        bmr = base_bmr + 5

    tdee = int(bmr * 1.375)

    if bmi < 18.5:
        target_calories = tdee + 400
        protein_g = int(weight * 2.0)
        recommendation = (
            f"Clinical Status: Underweight (BMI: {bmi:.2f}). "
            f"Estimated BMR: {int(bmr)} kcal | Target TDEE: {target_calories} kcal/day (Caloric Surplus). "
            f"Recommended Macros: Protein ~{protein_g}g/day, Healthy Fats & Complex Carbs. "
            f"Diet Guidance: Focus on nutrient-dense, frequent calorie-rich meals (nuts, lean proteins, avocados, whole grains)."
        )
        return "Underweight", "Below adult BMI reference range", "Review advised", recommendation

    elif bmi < 25:
        target_calories = tdee
        protein_g = int(weight * 1.6)
        recommendation = (
            f"Clinical Status: Normal Weight (BMI: {bmi:.2f}). "
            f"Estimated BMR: {int(bmr)} kcal | Maintenance TDEE: {target_calories} kcal/day. "
            f"Recommended Macros: Protein ~{protein_g}g/day, Balanced Carbohydrates and Fiber. "
            f"Diet Guidance: Maintain a balanced diet, stay hydrated (2-3 liters/day), and incorporate whole foods."
        )
        return "Normal", "Within adult BMI reference range", "Routine", recommendation

    elif bmi < 30:
        target_calories = tdee - 500
        protein_g = int(weight * 1.8)
        recommendation = (
            f"Clinical Status: Overweight (BMI: {bmi:.2f}). "
            f"Estimated BMR: {int(bmr)} kcal | Target TDEE: {target_calories} kcal/day (Caloric Deficit). "
            f"Recommended Macros: High Protein (~{protein_g}g/day), Controlled Carbs, High Fiber. "
            f"Diet Guidance: Prioritize whole foods, lean proteins, vegetables, and portion control."
        )
        return "Overweight", "Above adult BMI reference range", "Review advised", recommendation

    else:
        target_calories = max(1200, tdee - 750)
        protein_g = int(weight * 2.0)
        recommendation = (
            f"🚨 CLINICAL OBESITY DETECTED (BMI: {bmi:.2f}) - AI SPECIALIZED DIET PLAN:\n"
            f"• Target Caloric Intake: ~{target_calories} kcal/day (Supervised Caloric Deficit).\n"
            f"• Macronutrient Split: High Protein (~{protein_g}g/day to preserve muscle mass), Low-Glycemic Carbs, Healthy Fats.\n"
            f"• Recommended Diet: High-fiber leafy greens, cruciferous vegetables, lean poultry, fish, eggs, legumes, and minimal processed sugars.\n"
            f"• Hydration: Drink 2.5 to 3 liters of water daily (have 1 glass 30 minutes before meals to promote satiety).\n"
            f"• Action Plan: Combine with structured low-impact physical activity (e.g., brisk walking/swimming 30 mins/day) and consult a physician."
        )
        return "Obesity", "Above adult BMI reference range", "Review advised", recommendation


def read_patient_form():
    name = request.form.get("name", "").strip()
    gender = request.form.get("gender", "").strip()
    if not name or len(name) > 100:
        raise ValueError("Enter a patient name (1 to 100 characters).")
    if gender not in {"Male", "Female", "Other"}:
        raise ValueError("Select a valid gender.")
    try:
        age = int(request.form.get("age", ""))
        height = float(request.form.get("height", ""))
        weight = float(request.form.get("weight", ""))
    except (TypeError, ValueError):
        raise ValueError("Enter valid numeric age, height and weight.") from None
    if not 1 <= age <= 120:
        raise ValueError("Age must be between 1 and 120 years.")
    if not math.isfinite(height) or not 0.3 <= height <= 3:
        raise ValueError("Height must be between 0.3 and 3 meters.")
    if not math.isfinite(weight) or not 0.1 <= weight <= 1000:
        raise ValueError("Weight must be between 0.1 and 1000 kg.")
    return name, age, gender, height, weight


def update_measurements(patient, age, gender, height, weight):
    bmi = round(weight / (height * height), 2)
    status, nutrition, risk, recommendation = calculate_health(bmi, age, gender, weight, height)
    patient.height = height
    patient.weight = weight
    patient.bmi = bmi
    patient.bmi_status = status
    patient.nutrition_status = nutrition
    patient.risk_level = risk
    patient.recommendation = recommendation


def save_history(patient, when):
    db.session.add(AssessmentHistory(
        patient_id=patient.id,
        date=when,
        weight=patient.weight,
        bmi=patient.bmi,
        bmi_status=patient.bmi_status,
        risk_level=patient.risk_level,
        recommendation=patient.recommendation,
    ))


def get_delete_token():
    if "delete_token" not in session:
        session["delete_token"] = secrets.token_urlsafe(32)
    return session["delete_token"]


def dashboard_data(query=""):
    filtered = Patient.query
    if query:
        filtered = filtered.filter(Patient.name.ilike(f"%{query}%"))
    patients = filtered.order_by(Patient.id.desc()).all()
    return {
        "patients": patients,
        "total": Patient.query.count(),
        "query": query,
        "underweight": Patient.query.filter_by(bmi_status="Underweight").count(),
        "normal": Patient.query.filter_by(bmi_status="Normal").count(),
        "overweight": Patient.query.filter_by(bmi_status="Overweight").count(),
        "obesity": Patient.query.filter_by(bmi_status="Obesity").count(),
        "age_specific": Patient.query.filter_by(bmi_status="Age-specific assessment").count(),
        "delete_token": get_delete_token(),
    }


@app.route("/")
def home():
    data = dashboard_data()
    data["shown"] = len(data["patients"])
    return render_template("dashboard.html", **data)


@app.route("/search")
def search_patient():
    query = request.args.get("query", "").strip()[:100]
    data = dashboard_data(query)
    data["shown"] = len(data["patients"])
    return render_template("dashboard.html", **data)


@app.route("/add", methods=["GET", "POST"])
def add_patient():
    if request.method == "GET":
        return render_template("patient.html")
    try:
        name, age, gender, height, weight = read_patient_form()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("add_patient"))

    patient = Patient(name=name, age=age, gender=gender)
    update_measurements(patient, age, gender, height, weight)
    now = utc_now()
    patient.assessment_date = now
    db.session.add(patient)
    db.session.flush()
    save_history(patient, now)
    db.session.commit()
    flash("Patient and first assessment saved.", "success")
    return redirect(url_for("home"))


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_patient(id):
    patient = db.session.get(Patient, id)
    if patient is None:
        abort(404)
    if request.method == "GET":
        return render_template("edit_patient.html", patient=patient)
    try:
        name, age, gender, height, weight = read_patient_form()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("edit_patient", id=id))

    changed = (
        patient.height is None or patient.weight is None
        or not math.isclose(patient.height, height, abs_tol=1e-9, rel_tol=0)
        or not math.isclose(patient.weight, weight, abs_tol=1e-9, rel_tol=0)
        or patient.age != age
    )
    patient.name, patient.age, patient.gender = name, age, gender
    update_measurements(patient, age, gender, height, weight)
    if changed:
        now = utc_now()
        patient.assessment_date = now
        save_history(patient, now)
    db.session.commit()
    flash("Patient updated successfully.", "success")
    return redirect(url_for("home"))


@app.route("/delete/<int:id>", methods=["POST"])
def delete_patient(id):
    supplied = request.form.get("delete_token", "")
    expected = session.get("delete_token", "")
    if not expected or not secrets.compare_digest(supplied, expected):
        abort(400, description="Invalid delete token. Reload the dashboard.")
    patient = db.session.get(Patient, id)
    if patient is None:
        abort(404)
    AssessmentHistory.query.filter_by(patient_id=id).delete(synchronize_session=False)
    db.session.delete(patient)
    db.session.commit()
    session.pop("delete_token", None)
    flash("Patient and assessment history deleted.", "success")
    return redirect(url_for("home"))


@app.route("/report/<int:id>")
def report(id):
    patient = db.session.get(Patient, id)
    if patient is None:
        abort(404)
    return render_template("report.html", patient=patient)


@app.route("/history/<int:id>")
def history(id):
    patient = db.session.get(Patient, id)
    if patient is None:
        abort(404)
    records = (
        AssessmentHistory.query.filter_by(patient_id=id)
        .order_by(AssessmentHistory.date.asc(), AssessmentHistory.id.asc()).all()
    )
    first = records[0] if records else None
    last = records[-1] if records else None
    return render_template(
        "history.html",
        patient=patient,
        records=records,
        visit_count=len(records),
        bmi_change=(round(last.bmi - first.bmi, 2)
                    if first and last and first.bmi is not None and last.bmi is not None else None),
        weight_change=(round(last.weight - first.weight, 2)
                       if first and last and first.weight is not None and last.weight is not None else None),
        chart_dates=[r.date.strftime("%d %b %Y, %H:%M") if r.date else "Unknown" for r in records],
        chart_bmi=[r.bmi for r in records],
        chart_weights=[r.weight for r in records],
    )


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    """Admin-only user management page; user.html should post username/password/role here."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "doctor").strip().lower()
        if not 3 <= len(username) <= 40:
            flash("Username must be between 3 and 40 characters.", "error")
            return redirect(url_for("users"))
        if len(password) < 12:
            flash("Password must be at least 12 characters.", "error")
            return redirect(url_for("users"))
        if role not in {"admin", "doctor"}:
            flash("Select a valid account role.", "error")
            return redirect(url_for("users"))
        exists = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if exists:
            flash("That username is already in use.", "error")
            return redirect(url_for("users"))
        db.session.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True,
        ))
        db.session.commit()
        flash(f"{role.title()} account created successfully.", "success")
        return redirect(url_for("users"))
    return render_template("user.html", users=User.query.order_by(User.username.asc()).all(), roles=("admin", "doctor"))


@app.route("/download_report/<int:id>")
def download_report(id):
    patient = db.session.get(Patient, id)
    if patient is None:
        abort(404)
    pdf = BytesIO()
    doc = SimpleDocTemplate(pdf, pagesize=letter, leftMargin=48, rightMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    date_text = patient.assessment_date.strftime("%d %b %Y, %H:%M UTC") if patient.assessment_date else "Not recorded"
    fields = [
        ("Patient ID", patient.id), ("Name", patient.name),
        ("Age", f"{patient.age} years" if patient.age is not None else "-"),
        ("Gender", patient.gender),
        ("Height", f"{patient.height} meters" if patient.height is not None else "-"),
        ("Weight", f"{patient.weight} kg" if patient.weight is not None else "-"),
        ("BMI", patient.bmi), ("BMI category", patient.bmi_status),
        ("Nutrition screening", patient.nutrition_status), ("BMI screening flag", patient.risk_level),
        ("Assessment date", date_text), ("Recommendation", patient.recommendation),
    ]
    rows = [[Paragraph(f"<b>{escape(str(key))}</b>", styles["BodyText"]),
             Paragraph(escape(str(value if value is not None else "-")), styles["BodyText"])]
            for key, value in fields]
    table = Table(rows, colWidths=[145, 365], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.lightgrey),
    ]))
    doc.build([
        Paragraph("HINAP Health Assessment Report", styles["Title"]),
        Spacer(1, 20), table, Spacer(1, 20),
        Paragraph("BMI is a screening measurement, not a diagnosis. Patients under 20 require age-specific interpretation.", styles["BodyText"]),
    ])
    pdf.seek(0)
    return send_file(pdf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"HINAP_Patient_{patient.id}_Report.pdf")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Creates missing tables; it does not erase existing records.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG", "1") == "1")