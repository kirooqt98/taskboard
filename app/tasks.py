from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db

bp = Blueprint("tasks", __name__)

MAX_TITLE, MAX_NOTES = 120, 2000


def _own_task(task_id):
    """Fetch a task only if it belongs to the logged-in user (prevents IDOR)."""
    task = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, g.user["id"])
    ).fetchone()
    if task is None:
        abort(404)
    return task


def _clean(form):
    title = form.get("title", "").strip()
    notes = form.get("notes", "").strip()
    if not title:
        return None, None, "Title is required."
    if len(title) > MAX_TITLE or len(notes) > MAX_NOTES:
        return None, None, f"Title max {MAX_TITLE} chars, notes max {MAX_NOTES}."
    return title, notes, None


@bp.route("/")
@login_required
def index():
    show = request.args.get("show", "all")
    sql = "SELECT * FROM tasks WHERE user_id = ?"
    if show == "open":
        sql += " AND done = 0"
    elif show == "done":
        sql += " AND done = 1"
    else:
        show = "all"
    rows = get_db().execute(sql + " ORDER BY done, created_at DESC, id DESC", (g.user["id"],)).fetchall()
    return render_template("dashboard.html", tasks=rows, show=show)


@bp.route("/tasks", methods=("POST",))
@login_required
def create():
    title, notes, error = _clean(request.form)
    if error:
        flash(error, "error")
    else:
        db = get_db()
        db.execute("INSERT INTO tasks (user_id, title, notes) VALUES (?, ?, ?)", (g.user["id"], title, notes))
        db.commit()
    return redirect(url_for("tasks.index"))


@bp.route("/tasks/<int:task_id>/edit", methods=("GET", "POST"))
@login_required
def edit(task_id):
    task = _own_task(task_id)
    if request.method == "POST":
        title, notes, error = _clean(request.form)
        if error:
            flash(error, "error")
        else:
            db = get_db()
            db.execute("UPDATE tasks SET title = ?, notes = ? WHERE id = ? AND user_id = ?",
                       (title, notes, task_id, g.user["id"]))
            db.commit()
            return redirect(url_for("tasks.index"))
    return render_template("edit.html", task=task)


@bp.route("/tasks/<int:task_id>/toggle", methods=("POST",))
@login_required
def toggle(task_id):
    _own_task(task_id)
    db = get_db()
    db.execute("UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?", (task_id, g.user["id"]))
    db.commit()
    return redirect(url_for("tasks.index"))


@bp.route("/tasks/<int:task_id>/delete", methods=("POST",))
@login_required
def delete(task_id):
    _own_task(task_id)
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, g.user["id"]))
    db.commit()
    return redirect(url_for("tasks.index"))
