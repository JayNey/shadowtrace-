"""Fault-injection package marker.

ISSUE-283 SIGKILL probe/tasks live under ``scripts.celery_sigkill_tasks`` so the
production image (no ``backend/tests/``) can import them. This package remains
for documentation only.
"""
