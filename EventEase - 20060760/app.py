import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "change_this_to_a_random_secret_key"

# Database file will live here
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "events.sqlite3")


# DB HELPER FUNCTIONS 

def get_db():
    """Get a connection for the current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the DB connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()



def init_db():
    print(">>> init_db() started")
    try:
        db = get_db()

        print(">>> Creating users table...")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        print(">>> Creating events table...")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                location TEXT,
                date_time TEXT NOT NULL,
                seats_total INTEGER NOT NULL,
                seats_taken INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        print(">>> Creating registrations table...")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            );
            """
        )

        db.commit()

        print(">>> Checking for admin user...")
        cur = db.execute("SELECT id FROM users WHERE email = ?", ("admin@example.com",))
        admin = cur.fetchone()

        if admin is None:
            print(">>> Creating default admin...")
            password_hash = generate_password_hash("admin123")
            db.execute(
                "INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                ("Admin User", "admin@example.com", password_hash, 1),
            )
            db.commit()

        print(">>> init_db() finished successfully")

    except Exception as e:
        print(">>> ERROR IN init_db():", e)




# AUTH HELPERS 

def current_user():
    """Return the currently logged-in user row, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def login_required(view_func):
    """Simple decorator to require login."""
    from functools import wraps

    @wraps(view_func)
    def wrapped_view(**kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view_func(**kwargs)

    return wrapped_view


def admin_required(view_func):
    """Decorator to require admin role."""
    from functools import wraps

    @wraps(view_func)
    def wrapped_view(**kwargs):
        user = current_user()
        if not user or user["is_admin"] != 1:
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return view_func(**kwargs)

    return wrapped_view

print(">>> Finished DB functions — entering route section")

#  ROUTES: PUBLIC PAGES 
print("Flask is loading routes now...")

@app.route("/")
def index():
    category = request.args.get("category", "").strip()

    db = get_db()

    if category:
        cur = db.execute(
            "SELECT * FROM events WHERE category = ? ORDER BY date_time ASC",
            (category,)
        )
    else:
        cur = db.execute(
            "SELECT * FROM events ORDER BY date_time ASC"
        )

    events = cur.fetchall()

    return render_template("index.html", events=events, user=current_user(), selected_category=category)


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()

    db = get_db()
    cur = db.execute(
        "SELECT * FROM events WHERE title LIKE ? OR description LIKE ? ORDER BY date_time ASC",
        (f"%{query}%", f"%{query}%")
    )
    events = cur.fetchall()

    return render_template("search_results.html", events=events, query=query, user=current_user())



@app.route("/event/<int:event_id>")
def event_detail(event_id):
    db = get_db()
    cur = db.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    event = cur.fetchone()
    if event is None:
        flash("Event not found.", "danger")
        return redirect(url_for("index"))

    # how many seats left
    seats_left = event["seats_total"] - event["seats_taken"]
    return render_template(
        "event_detail.html",
        event=event,
        seats_left=seats_left,
        user=current_user(),
    )


@app.route("/event/<int:event_id>/register", methods=["POST"])
@login_required
def register_event(event_id):
    db = get_db()

    # Check event exists
    cur = db.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    event = cur.fetchone()
    if event is None:
        flash("Event not found.", "danger")
        return redirect(url_for("index"))

    seats_left = event["seats_total"] - event["seats_taken"]
    if seats_left <= 0:
        flash("No seats left for this event.", "danger")
        return redirect(url_for("event_detail", event_id=event_id))

    user = current_user()

    # Check if already registered
    cur = db.execute(
        "SELECT id FROM registrations WHERE user_id = ? AND event_id = ?",
        (user["id"], event_id),
    )
    existing = cur.fetchone()
    if existing:
        flash("You are already registered for this event.", "info")
        return redirect(url_for("event_detail", event_id=event_id))

    # Insert registration
    now_str = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO registrations (user_id, event_id, created_at) VALUES (?, ?, ?)",
        (user["id"], event_id, now_str),
    )
    # Update seats_taken
    db.execute(
        "UPDATE events SET seats_taken = seats_taken + 1 WHERE id = ?",
        (event_id,),
    )
    db.commit()

    flash("Successfully registered for the event!", "success")
    return redirect(url_for("my_registrations"))


@app.route("/my-registrations")
@login_required
def my_registrations():
    db = get_db()
    user = current_user()
    cur = db.execute(
        """
        SELECT r.id as reg_id, r.created_at, e.*
        FROM registrations r
        JOIN events e ON r.event_id = e.id
        WHERE r.user_id = ?
        ORDER BY e.date_time ASC
        """,
        (user["id"],),
    )
    regs = cur.fetchall()
    return render_template(
        "my_registrations.html", registrations=regs, user=user
    )


# ROUTES: AUTH 

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, password_hash),
        )
        db.commit()
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    db = get_db()
    user = current_user()

    # Count registrations
    cur = db.execute(
        "SELECT COUNT(*) as total FROM registrations WHERE user_id = ?",
        (user["id"],)
    )
    reg_count = cur.fetchone()["total"]

    return render_template("profile.html", user=user, reg_count=reg_count)



# ROUTES: ADMIN 
@app.route("/admin/events")
@admin_required
def admin_events():
    db = get_db()
    cur = db.execute("SELECT * FROM events ORDER BY date_time ASC")
    events = cur.fetchall()
    return render_template(
        "admin_events.html", events=events, user=current_user()
    )


@app.route("/admin/events/new", methods=["GET", "POST"])
@admin_required
def admin_create_event():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        date_time = request.form.get("date_time", "").strip()
        seats_total = request.form.get("seats_total", "").strip()
        image_url = request.form.get("image_url", "").strip()
        category = request.form.get("category", "").strip()


        if not title or not date_time or not seats_total:
            flash("Title, date/time and total seats are required.", "danger")
            return redirect(url_for("admin_create_event"))

        try:
            seats_total_int = int(seats_total)
            if seats_total_int <= 0:
                raise ValueError
        except ValueError:
            flash("Total seats must be a positive integer.", "danger")
            return redirect(url_for("admin_create_event"))

        db = get_db()
        db.execute(
            """
            INSERT INTO events (title, description, location, date_time, seats_total, seats_taken, category, image_url)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)

            """,
            (title, description, location, date_time, seats_total_int, category, image_url),
        )

        db.commit()
        flash("Event created successfully.", "success")
        return redirect(url_for("admin_events"))

    return render_template("admin_event_form.html", event=None, user=current_user())


@app.route("/admin/events/<int:event_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_event(event_id):
    db = get_db()
    cur = db.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    event = cur.fetchone()
    if event is None:
        flash("Event not found.", "danger")
        return redirect(url_for("admin_events"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        image_url = request.form.get("image_url", "").strip()
        location = request.form.get("location", "").strip()
        category = request.form.get("category", "").strip()
        date_time = request.form.get("date_time", "").strip()
        seats_total = request.form.get("seats_total", "").strip()


        if not title or not date_time or not seats_total:
            flash("Title, date/time and total seats are required.", "danger")
            return redirect(url_for("admin_edit_event", event_id=event_id))

        try:
            seats_total_int = int(seats_total)
            if seats_total_int <= 0:
                raise ValueError
        except ValueError:
            flash("Total seats must be a positive integer.", "danger")
            return redirect(url_for("admin_edit_event", event_id=event_id))

        # Adjust seats_taken if seats_total decreased below seats_taken
        seats_taken = event["seats_taken"]
        if seats_total_int < seats_taken:
            seats_taken = seats_total_int

        db.execute(
            """
            UPDATE events
            SET title = ?, description = ?, location = ?, date_time = ?, seats_total = ?, seats_taken = ?, category = ?, image_url = ?
            WHERE id = ?

            """,
            (title, description, location, date_time, seats_total_int, seats_taken, category, image_url, event_id),
        )
        db.commit()
        flash("Event updated successfully.", "success")
        return redirect(url_for("admin_events"))

    return render_template("admin_event_form.html", event=event, user=current_user())


@app.route("/admin/events/<int:event_id>/delete", methods=["POST"])
@admin_required
def admin_delete_event(event_id):
    db = get_db()

    # Delete registrations first to keep DB clean
    db.execute("DELETE FROM registrations WHERE event_id = ?", (event_id,))
    db.execute("DELETE FROM events WHERE id = ?", (event_id,))
    db.commit()
    flash("Event deleted.", "info")
    return redirect(url_for("admin_events"))


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)

