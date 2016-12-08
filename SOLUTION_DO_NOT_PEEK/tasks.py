"""Async tasks for basic iostat REST service."""

import subprocess

import celery
from celery import signals


app = celery.Celery("tasks",
                    broker="sqla+sqlite:///celerydb.sqlite",
                    backend="db+sqlite:///celerydb.sqlite")
app.conf.CELERY_IGNORE_RESULT = False
app.conf.CELERY_TRACK_STARTED = True


@signals.after_task_publish.connect
def update_sent_state(sender=None, body=None, **kwargs):
    # the task may not exist if sent using `send_task` which
    # sends tasks by name, so fall back to the default result backend
    # if that is the case.
    task = app.tasks.get(sender)
    backend = task.backend if task else app.backend
    backend.store_result(body['id'], None, "QUEUED")


@app.task
def iostat(count, wait):
    cmd = ["iostat", "-d", str(wait), str(count)]
    return {"iostat": subprocess.check_output(cmd)}
