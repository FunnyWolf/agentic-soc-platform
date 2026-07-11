from django.test import TestCase

from apps.accounts.models import User
from apps.cases.models import Case
from apps.playbooks.models import Playbook, PlaybookJobStatus
from .models import InboxMessageRecipient
from .notifications import notify_case_assignment, notify_playbook_completion


class NotificationPreferenceTests(TestCase):
    def test_playbook_completion_respects_preference_and_serializes_metadata_ids(self):
        requester = User.objects.create_user(username="requester", password="x")
        case = Case.objects.create(title="Notification case")
        playbook = Playbook.objects.create(
            case=case,
            name="Investigation",
            user=requester,
            job_status=PlaybookJobStatus.SUCCESS,
            remark="done",
        )

        requester.notify_on_playbook_completion = False
        requester.save(update_fields=["notify_on_playbook_completion"])
        self.assertIsNone(notify_playbook_completion(playbook))

        requester.notify_on_playbook_completion = True
        requester.save(update_fields=["notify_on_playbook_completion"])
        message = notify_playbook_completion(playbook)

        self.assertIsNotNone(message)
        self.assertTrue(InboxMessageRecipient.objects.filter(message=message, user=requester).exists())
        self.assertEqual(message.metadata["source"], "playbook_completion")
        self.assertEqual(message.metadata["playbook_pk"], str(playbook.pk))
        self.assertEqual(message.metadata["case_pk"], str(case.pk))

    def test_case_assignment_respects_preference_and_serializes_metadata_ids(self):
        actor = User.objects.create_user(username="actor", password="x")
        assignee = User.objects.create_user(username="assignee", password="x")
        case = Case.objects.create(title="Assigned case", assignee=assignee)

        assignee.notify_on_case_assignment = False
        assignee.save(update_fields=["notify_on_case_assignment"])
        self.assertIsNone(notify_case_assignment(case, previous_assignee_id=None, actor=actor))

        assignee.notify_on_case_assignment = True
        assignee.save(update_fields=["notify_on_case_assignment"])
        message = notify_case_assignment(case, previous_assignee_id=None, actor=actor)

        self.assertIsNotNone(message)
        self.assertTrue(InboxMessageRecipient.objects.filter(message=message, user=assignee).exists())
        self.assertEqual(message.metadata["source"], "case_assignment")
        self.assertEqual(message.metadata["case_pk"], str(case.pk))
