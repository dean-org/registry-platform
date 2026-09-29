import importlib
import logging
import uuid
from datetime import datetime

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.service import BaseService
from sqlalchemy import Date as SQLDate, and_, case, exists, func, inspect, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..errors import G2PRegistryErrorCodes, G2PRegistryException
from ..repositories.register_repository import RegisterRecordRepository
from iam_core.helpers.data_policy_helper import DataPolicyHelper
from .g2p_awe_integration_service import G2PAweIntegrationService
from .g2p_awe_status_reconcile import (
    REGISTRY_INTAKE_FORM_ARTIFACT,
    reconcile_artifact_status_summary,
)
from ..models import (
    ApprovalStatusEnum,
    ChangeRequestSourceEnum,
    DeduplicationIntakeFormRegisterResult,
    DeduplicationIntakeFormIntakeFormResult,
    G2PFunctionalIdGenerationQueue,
    G2PIntakeFormDefinition,
    G2PIntakeFormSubmission,
    G2PIntakeFormSubmissionDocument,
    G2PIntakeFormUITab,
    G2PIntakeFormUITabSection,
    G2PRegisterDefinition,
    G2PRegisterSchema,
    G2PRegisterDocumentHistory,
    G2PRegisterSection,
    G2PRegisterSectionDocument,
    IntakeFormStatusEnum,
    ProcessStatusEnum,
    RegisterPurposeEnum,
    SubmissionSourceEnum,
)
from .g2p_attribute_value_validator import G2PAttributeValueValidator
from .filter_builder import FilterBuilder
from ..schemas import (
    DocumentAttachment,
    DeduplicationIntakeFormRegisterResultData,
    DeduplicationIntakeFormIntakeFormResultData,
    DisplayField,
    IntakeAllowedParentsData,
    SectionPayloadInput,
    SectionPayloadResponseItem,
    SubmissionResponsePayload,
    IntakeFormSubmissionsSummaryData
)
from .g2p_verification_service import G2PRegisterVerificationService
from .g2p_intake_form_link_service import G2PIntakeFormLinkService

_DOMAIN_MODELS_MODULE = "openg2p_registry_extensions.register_domain.models"
_DOMAIN_SCHEMAS_MODULE = "openg2p_registry_extensions.register_domain.schemas"
_INTAKE_CLASS_PREFIX = "G2PIntakeForm"
_logger = logging.getLogger("g2p-intake-form-data-service")


class G2PIntakeFormDataService(BaseService):
    async def get_intake_allowed_parents(
        self,
        submission_id: str,
        section_register_id: str,
        form_register_id: str,
    ) -> IntakeAllowedParentsData:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            await self._get_submission_or_error(submission_id, session)
            link_service = G2PIntakeFormLinkService.get_component()
            candidates = await link_service.list_intake_parent_candidates(
                submission_id, section_register_id, session
            )
            section_register = await self._get_register_definition(
                section_register_id, session
            )
            return IntakeAllowedParentsData(
                parent_register_id=candidates.parent_register_id,
                parent_register_mnemonic=candidates.parent_register_mnemonic,
                link_required=link_service.is_parent_link_required(
                    section_register, form_register_id, section_register_id
                ),
                allow_live_parent=link_service.is_optional_subject_parent_link(
                    section_register, form_register_id, section_register_id
                ),
                requires_selection=candidates.requires_selection,
                allowed_parents=candidates.allowed_parents,
            )

    async def save_intake_form_submission(
        self,
        submission_id: str | None,
        section_id: str,
        section_payload: list[dict],
        section_register_id: str,
        form_id: str,
        register_id: str,
        created_by: str,
        documents: list[DocumentAttachment] | None = None,
    ) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self.save_intake_form_submission_with_session(
                submission_id,
                section_id,
                section_payload,
                section_register_id,
                form_id,
                register_id,
                created_by,
                session,
                documents=documents,
            )
            await session.commit()
            return await self.get_submission_payload(submission.submission_id)

    async def save_intake_form_submission_with_session(
        self,
        submission_id: str | None,
        section_id: str,
        section_payload: list[dict],
        section_register_id: str,
        form_id: str,
        register_id: str,
        created_by: str,
        session,
        documents: list[DocumentAttachment] | None = None,
    ) -> G2PIntakeFormSubmission:
        submission = await self._get_or_create_draft_submission(
            submission_id,
            form_id,
            register_id,
            created_by,
            session,
        )
        _section = await self._get_section_or_error(section_id, session)
        intake_class = await self._resolve_intake_form_class(section_register_id, session)

        section_register_definition = await self._get_register_definition(section_register_id, session)
        module = importlib.import_module("openg2p_registry_extensions.register_domain.factory")
        domain_factory = getattr(module, "G2PRegisterDomainFactory").get_component()
        domain_service = domain_factory.get_domain_service(section_register_definition.register_mnemonic)
        # Same coded-value check the change-request path applies. Intake forms
        # are a second way in, so leaving it out here would mean values rejected
        # at one door are accepted at the other.
        await G2PAttributeValueValidator.get_component().validate_records(section_payload or [])

        if domain_service:
            await domain_service.validate_domain_attributes(section_payload or [],section_id=section_id,)

        existing_rows = await self._get_intake_rows(intake_class, submission.submission_id, session)
        incoming_ids = await self._upsert_intake_rows(
            intake_class,
            submission,
            section_payload or [],
            existing_rows,
            created_by,
            session,
            form_register_id=register_id,
            section_register_id=section_register_id,
            domain_service=domain_service,
        )
        deleted_ids = await self._delete_missing_intake_rows(existing_rows, incoming_ids, session)
        await session.flush()
        await G2PIntakeFormLinkService.get_component().null_child_links_for_deleted_parents(
            submission.submission_id,
            deleted_ids,
            session,
        )

        submission.form_id = form_id
        submission.register_id = register_id
        submission.draft_status = IntakeFormStatusEnum.DRAFT.value
        submission.last_updated_at = datetime.now()
        session.add(submission)
        await self._upsert_submission_section_documents(
            submission, section_id, documents, session
        )
        await session.flush()
        return submission

    async def _upsert_submission_section_documents(
        self,
        submission: G2PIntakeFormSubmission,
        section_id: str,
        documents: list[DocumentAttachment] | None,
        session,
    ) -> None:
        """
        Make junction rows match the desired documents for this section
        (same idea as intake row upsert + delete-missing).

        None = no-op; [] = clear; list = desired full set (diff by document_id).
        """
        if documents is None:
            return

        existing_rows = (
            await session.execute(
                select(G2PIntakeFormSubmissionDocument).where(
                    G2PIntakeFormSubmissionDocument.submission_id == submission.submission_id,
                    G2PIntakeFormSubmissionDocument.section_id == section_id,
                )
            )
        ).scalars().all()
        existing_by_id = {row.document_id: row for row in existing_rows}
        desired_by_id = {doc.document_id: doc for doc in documents}
        desired_ids = set(desired_by_id)

        for row in existing_rows:
            if row.document_id not in desired_ids:
                await session.delete(row)
            else:
                row.label = desired_by_id[row.document_id].label

        to_add = desired_ids - set(existing_by_id)
        if not to_add:
            return

        from .g2p_document_service import G2PDocumentService

        await G2PDocumentService.get_component().validate_documents_exist(
            session, list(to_add)
        )
        for document_id in to_add:
            doc = desired_by_id[document_id]
            session.add(
                G2PIntakeFormSubmissionDocument(
                    submission_id=submission.submission_id,
                    section_id=section_id,
                    document_id=document_id,
                    label=doc.label,
                )
            )

    async def _get_or_create_draft_submission(
        self,
        submission_id: str | None,
        form_id: str,
        register_id: str,
        created_by: str,
        session,
    ) -> G2PIntakeFormSubmission:
        if submission_id:
            return await self._get_draft_submission_or_error(submission_id, session)
        return await self._create_draft_submission(form_id, register_id, created_by, session)

    async def _create_draft_submission(
        self,
        form_id: str,
        register_id: str,
        created_by: str,
        session,
    ) -> G2PIntakeFormSubmission:
        now = datetime.now()
        await self._validate_form(form_id, register_id, session)
        submission = G2PIntakeFormSubmission(
            form_id=form_id,
            register_id=register_id,
            draft_status=IntakeFormStatusEnum.DRAFT.value,
            approval_status=ApprovalStatusEnum.PENDING.value,
            first_created_at=now,
            last_updated_at=now,
            created_by=created_by,
            submission_source=ChangeRequestSourceEnum.STAFF_PORTAL.value,
            partner_id=None,
            register_ingest_process_status=ProcessStatusEnum.NOT_APPLICABLE.value,
            number_of_verifications_required=await self._get_form_verification_requirement(form_id, session),
            number_of_verifications_done=0,
        )
        session.add(submission)
        await session.flush()
        return submission

    async def _get_draft_submission_or_error(self, submission_id: str, session) -> G2PIntakeFormSubmission:
        submission = await self._get_submission_or_error(submission_id, session)
        self._ensure_submission_state(
            submission,
            allowed_draft_status={IntakeFormStatusEnum.DRAFT.value},
            message=f"Submission '{submission_id}' can only be saved while in DRAFT state",
        )
        return submission

    async def _get_section_or_error(self, section_id: str, session) -> G2PRegisterSection:
        section = await session.get(G2PRegisterSection, section_id)
        if not section:
            self._invalid_request(f"Section '{section_id}' was not found")
        return section

    async def _resolve_intake_form_class(self, section_register_id: str, session):
        register_definition = await self._get_register_definition(section_register_id, session)
        module = importlib.import_module(_DOMAIN_MODELS_MODULE)
        implementation_class_name = f"G2PIntakeForm{register_definition.register_mnemonic}"
        return getattr(module, implementation_class_name)

    async def _get_intake_rows(self, intake_class, submission_id: str, session) -> dict[str, object]:
        rows = (
            await session.execute(select(intake_class).where(intake_class.submission_id == submission_id))
        ).scalars().all()
        return {row.internal_record_id: row for row in rows if getattr(row, "internal_record_id", None)}

    async def _get_intake_rows_list(self, intake_class, submission_id: str, session) -> list[object]:
        return (
            await session.execute(select(intake_class).where(intake_class.submission_id == submission_id))
        ).scalars().all()

    async def _build_intake_match_subquery(
        self,
        register_id: str,
        search_text: str | None,
        filter_by: dict | None,
        intake_class,
        session,
        data_policies: list[dict] | None = None,
    ):
        conditions: list = []
        if search_text:
            conditions.append(intake_class.search_text.ilike(f"%{search_text}%"))
        if filter_by:
            filter_schema = await self._get_filter_schema(register_id, session)
            try:
                conditions.extend(FilterBuilder(filter_schema).build_conditions(filter_by, intake_class))
            except ValueError as validation_error:
                self._invalid_request(str(validation_error))

        policy_condition = await self._build_intake_policy_condition(
            register_id, intake_class, data_policies, session
        )
        if policy_condition is not None:
            conditions.append(policy_condition)

        if not conditions:
            return None

        return select(intake_class.submission_id).where(*conditions).distinct()

    async def _get_filter_schema(self, register_id: str, session) -> list[dict]:
        register_schema = await session.get(G2PRegisterSchema, register_id)
        return register_schema.filter_schema if register_schema and register_schema.filter_schema else []

    async def _count_submissions(self, base_filters: list, session) -> int:
        query = select(func.count()).select_from(G2PIntakeFormSubmission).where(*base_filters)
        return (await session.execute(query)).scalar_one()

    async def _get_submissions_page(
        self,
        base_filters: list,
        sort_by: str | None,
        current_page: int,
        page_size: int,
        session,
    ) -> list[G2PIntakeFormSubmission]:
        query = select(G2PIntakeFormSubmission).where(*base_filters)
        query = self._apply_submission_sort(query, sort_by)
        query = self._apply_pagination(query, current_page, page_size)
        return (await session.execute(query)).scalars().all()

    async def _build_submission_search_payloads(
        self,
        submissions: list[G2PIntakeFormSubmission],
        intake_class,
        display_fields_sorted: list,
        session,
    ) -> list[SubmissionResponsePayload]:
        payloads: list[SubmissionResponsePayload] = []
        for submission in submissions:
            intake_rows = await self._get_intake_rows_list(intake_class, submission.submission_id, session)
            source_row = intake_rows[0] if intake_rows else None
            record_name = getattr(source_row, "record_name", None) if source_row else None
            payload = self._build_submission_response_payload(submission, None, record_name)
            if display_fields_sorted:
                display_fields_list: list[DisplayField] = []
                for field_config in display_fields_sorted:
                    field_name: str = field_config.get("field_name")
                    value = getattr(source_row, field_name, None) if source_row else None
                    if value is not None and hasattr(value, "isoformat"):
                        value = value.isoformat()
                    if value is not None and not isinstance(value, str):
                        value = str(value)
                    display_fields_list.append(
                        DisplayField(
                            field_name=field_name,
                            value=value,
                            order=field_config.get("order", 999),
                        )
                    )
                payload.display_fields = display_fields_list if display_fields_list else None
            payloads.append(payload)
        return payloads

    async def _upsert_intake_rows(
        self,
        intake_class,
        submission: G2PIntakeFormSubmission,
        records: list[dict],
        existing_rows: dict[str, object],
        actor_name: str,
        session,
        form_register_id: str | None = None,
        section_register_id: str | None = None,
        domain_service=None,
    ) -> set[str]:
        link_service = G2PIntakeFormLinkService.get_component()
        has_link_column = (
            section_register_id is not None
            and link_service.intake_model_has_link_column(intake_class)
        )
        incoming_ids: set[str] = set()
        for record in records:
            payload = dict(record or {})
            if payload.get("edit_action") == "DELETE":
                continue

            record_data = self._build_intake_row_data(
                payload,
                intake_class,
                submission,
                actor_name,
            )
            internal_record_id = record_data["internal_record_id"]
            incoming_ids.add(internal_record_id)
            existing = existing_rows.get(internal_record_id)

            if has_link_column:
                existing_link = (
                    getattr(existing, "link_internal_record_id", None) if existing else None
                )
                resolved_link = await link_service.resolve_link_internal_record_id(
                    submission_id=submission.submission_id,
                    form_register_id=form_register_id,
                    section_register_id=section_register_id,
                    record=payload,
                    session=session,
                    existing_link=existing_link,
                    payload_specifies_link="link_internal_record_id" in payload,
                )
                record_data["link_internal_record_id"] = resolved_link
                if domain_service:
                    await domain_service.validate_intake_parent_link(
                        record_data, resolved_link, session
                    )

            if existing:
                await self._update_existing_record(existing, record_data, intake_class, session)
            else:
                session.add(intake_class(**record_data))
        await session.flush()
        return incoming_ids

    def _build_intake_row_data(
        self,
        payload_record: dict,
        intake_class,
        submission: G2PIntakeFormSubmission,
        actor_name: str,
    ) -> dict:
        payload_record["internal_record_id"] = payload_record.get("internal_record_id") or str(uuid.uuid4())
        record_data = self._build_record_data(payload_record, payload_record, intake_class)
        self._stamp_submission_row_fields(record_data, submission)
        self._set_data_if_column(record_data, intake_class, "created_by", actor_name or submission.created_by)
        self._set_data_if_column(record_data, intake_class, "created_at", submission.first_created_at)
        self._set_data_if_column(record_data, intake_class, "last_approved_at", submission.last_updated_at)
        self._set_data_if_column(record_data, intake_class, "last_approved_by", actor_name or submission.created_by)
        return record_data

    async def _delete_missing_intake_rows(
        self,
        existing_rows: dict[str, object],
        incoming_ids: set[str],
        session,
    ) -> set[str]:
        deleted_ids: set[str] = set()
        for internal_record_id, row in existing_rows.items():
            if internal_record_id not in incoming_ids:
                await session.delete(row)
                deleted_ids.add(internal_record_id)
        return deleted_ids

    async def create_submission(
        self,
        form_id: str,
        register_id: str,
        submission_source: str,
        partner_id: str | None,
        section_payloads: list[SectionPayloadInput] | None,
        created_by: str,
    ) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self.create_submission_with_session(
                form_id,
                register_id,
                submission_source,
                partner_id,
                section_payloads,
                created_by,
                session,
            )
            await session.commit()
            return await self.get_submission_payload(submission.submission_id)

    async def create_submission_with_session(
        self,
        form_id: str,
        register_id: str,
        submission_source: str,
        partner_id: str | None,
        section_payloads: list[SectionPayloadInput] | None,
        created_by: str,
        session,
    ) -> G2PIntakeFormSubmission:
        now = datetime.now()
        await self._validate_form(form_id, register_id, session)

        submission = G2PIntakeFormSubmission(
            form_id=form_id,
            register_id=register_id,
            draft_status=IntakeFormStatusEnum.DRAFT.value,
            approval_status=ApprovalStatusEnum.PENDING.value,
            first_created_at=now,
            last_updated_at=now,
            created_by=created_by,
            submission_source=self._normalize_submission_source(submission_source),
            partner_id=partner_id,
            register_ingest_process_status=ProcessStatusEnum.NOT_APPLICABLE.value,
            number_of_verifications_required=await self._get_form_verification_requirement(form_id, session),
            number_of_verifications_done=0,
        )
        session.add(submission)
        await session.flush()

        if section_payloads is not None:
            await self._replace_submission_sections(submission, section_payloads, created_by, session)

        await session.flush()
        return submission

    async def finalize_submission(
        self,
        submission_id: str,
        finalized_by: str | None = None,
        bearer_token: str | None = None,
        requester_sub: str | None = None,
    ) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self.finalize_submission_with_session(
                submission_id,
                session,
                finalized_by,
                bearer_token=bearer_token,
                requester_sub=requester_sub,
            )
            await session.commit()
            return await self.get_submission_payload(submission.submission_id)

    async def finalize_submission_with_session(
        self,
        submission_id: str,
        session,
        finalized_by: str | None = None,
        bearer_token: str | None = None,
        requester_sub: str | None = None,
    ) -> G2PIntakeFormSubmission:
        _ = finalized_by
        submission = await self._get_submission_or_error(submission_id, session)
        now = datetime.now()
        submission.draft_status = IntakeFormStatusEnum.FINAL.value
        submission.finalized_at = now
        submission.last_updated_at = now
        session.add(submission)
        await session.flush()
        section_payloads = await self._build_section_payloads(submission, session)
        register_definition = await self._get_register_definition(submission.register_id, session)
        intake_form = await self._validate_form(submission.form_id, submission.register_id, session)
        source_data = [
            record
            for section in section_payloads
            for record in (section.records or [])
            if isinstance(record, dict)
        ]
        await G2PAweIntegrationService.get_component().start_intake_submission_workflow(
            session,
            submission,
            bearer_token=bearer_token,
            requester=requester_sub or submission.created_by,
            record_name=self._extract_record_name(section_payloads),
            register_mnemonic=register_definition.register_mnemonic,
            intake_form_mnemonic=intake_form.form_mnemonic,
            source_data=source_data,
        )
        return submission

    async def approve_submission(self, submission_id: str, approved_by: str) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self._get_submission_or_error(submission_id, session)
            if submission.approval_status != ApprovalStatusEnum.PENDING.value:
                self._invalid_request(
                    f"Submission '{submission_id}' is already in approval_status '{submission.approval_status}'"
                )

            # Validate verifications
            if submission.number_of_verifications_required > 0:
                verification_service = G2PRegisterVerificationService.get_component()   
                _, number_of_verifications_done = await verification_service.get_verifications(
                        change_request_id=None,
                        submission_id=submission.submission_id
                    )
                if number_of_verifications_done < submission.number_of_verifications_required:
                    raise G2PRegistryException(
                        code=G2PRegistryErrorCodes.INTAKE_FORM_VERIFICATIONS_PENDING.value[1],
                        message=G2PRegistryErrorCodes.INTAKE_FORM_VERIFICATIONS_PENDING.value[0]
                    )

            now = datetime.now()
            submission.approval_status = ApprovalStatusEnum.APPROVED.value
            submission.approved_by = approved_by
            submission.approved_at = now
            submission.last_updated_at = now
            submission.register_ingest_process_status = ProcessStatusEnum.PENDING.value
            submission.register_ingest_process_last_error_code = None
            session.add(submission)
            await session.commit()
            return await self.get_submission_payload(submission.submission_id)

    async def reject_submission(self, submission_id: str, rejected_by: str) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self._get_submission_or_error(submission_id, session)
            if submission.approval_status != ApprovalStatusEnum.PENDING.value:
                self._invalid_request(
                    f"Submission '{submission_id}' is already in approval_status '{submission.approval_status}'"
                )

            now = datetime.now()
            submission.approval_status = ApprovalStatusEnum.REJECTED.value
            submission.approved_by = rejected_by
            submission.approved_at = now
            submission.last_updated_at = now
            session.add(submission)
            await session.commit()
            return await self.get_submission_payload(submission.submission_id)

    async def approve_submission_with_session(
        self,
        submission_id: str,
        session,
        approved_by: str | None = None,
    ) -> G2PIntakeFormSubmission:
        submission = await self._get_submission_or_error(submission_id, session)
        if submission.approval_status == ApprovalStatusEnum.APPROVED.value:
            return submission
        if submission.approval_status != ApprovalStatusEnum.PENDING.value:
            self._invalid_request(
                f"Submission '{submission_id}' is already in approval_status "
                f"'{submission.approval_status}'"
            )
        now = datetime.now()
        submission.approval_status = ApprovalStatusEnum.APPROVED.value
        submission.approved_by = approved_by or "system"
        submission.approved_at = now
        submission.last_updated_at = now
        submission.register_ingest_process_status = ProcessStatusEnum.PENDING.value
        submission.register_ingest_process_last_error_code = None
        session.add(submission)
        await session.flush()
        return submission

    async def reject_submission_with_session(
        self,
        submission_id: str,
        session,
        rejected_by: str | None = None,
    ) -> G2PIntakeFormSubmission:
        submission = await self._get_submission_or_error(submission_id, session)
        if submission.approval_status == ApprovalStatusEnum.REJECTED.value:
            return submission
        if submission.approval_status != ApprovalStatusEnum.PENDING.value:
            self._invalid_request(
                f"Submission '{submission_id}' is already in approval_status "
                f"'{submission.approval_status}'"
            )
        now = datetime.now()
        submission.approval_status = ApprovalStatusEnum.REJECTED.value
        submission.approved_by = rejected_by or "system"
        submission.approved_at = now
        submission.last_updated_at = now
        session.add(submission)
        await session.flush()
        return submission

    async def cancel_submission_with_session(
        self,
        submission_id: str,
        session,
        cancelled_by: str | None = None,
    ) -> G2PIntakeFormSubmission:
        submission = await self._get_submission_or_error(submission_id, session)
        if submission.approval_status == ApprovalStatusEnum.CANCELLED.value:
            return submission
        if submission.approval_status != ApprovalStatusEnum.PENDING.value:
            self._invalid_request(
                f"Submission '{submission_id}' is already in approval_status "
                f"'{submission.approval_status}'"
            )
        now = datetime.now()
        submission.approval_status = ApprovalStatusEnum.CANCELLED.value
        submission.approved_by = cancelled_by or "system"
        submission.approved_at = now
        submission.last_updated_at = now
        session.add(submission)
        await session.flush()
        return submission

    async def delete_submission(self, submission_id: str) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            response = await self.delete_submission_with_session(submission_id, session)
            await session.commit()
            return response

    async def delete_submission_with_session(
        self,
        submission_id: str,
        session,
    ) -> SubmissionResponsePayload:
        submission = await self._get_submission_or_error(submission_id, session)
        response = self._build_submission_response_payload(submission, None, None)
        await self._delete_submission_rows(submission, session)
        await session.flush()
        return response

    async def get_intake_form_submission(
        self,
        submission_id: str,
        data_policies: list[dict] | None = None,
    ) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self._ensure_submission_readable(
                submission_id, data_policies, session
            )

            sections = await self._build_section_payloads(submission, session)

            return self._build_submission_response_payload(
                submission,
                sections,
                self._extract_record_name(sections),
            )

    async def get_submission_payload(
        self,
        submission_id: str,
    ) -> SubmissionResponsePayload:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self._get_submission_or_error(submission_id, session)
            if submission.awe_request_id:
                await reconcile_artifact_status_summary(
                    session,
                    artifact_type=REGISTRY_INTAKE_FORM_ARTIFACT,
                    artifact_id=submission.submission_id,
                )
            sections = await self._build_section_payloads(submission, session)
            response = self._build_submission_response_payload(
                submission,
                sections,
                self._extract_record_name(sections),
            )
            await session.commit()
            return response

    async def search_submissions(
        self,
        register_id: str,
        search_text: str | None,
        current_page: int,
        page_size: int,
        sort_by: str | None = None,
        filter_by: dict | None = None,
        data_policies: list[dict] | None = None,
    ) -> tuple[list[SubmissionResponsePayload], int]:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            intake_class = await self._resolve_intake_form_class(register_id, session)
            match_subquery = await self._build_intake_match_subquery(
                register_id,
                search_text,
                filter_by,
                intake_class,
                session,
                data_policies,
            )
            base_filters = [G2PIntakeFormSubmission.register_id == register_id]
            if match_subquery is not None:
                base_filters.append(G2PIntakeFormSubmission.submission_id.in_(match_subquery))

            total_items = await self._count_submissions(base_filters, session)
            submissions = await self._get_submissions_page(
                base_filters,
                sort_by,
                current_page,
                page_size,
                session,
            )
            register_schema = await session.get(G2PRegisterSchema, register_id)
            search_result_schema: list = (
                register_schema.search_result_schema if register_schema and register_schema.search_result_schema else []
            )
            display_fields_sorted: list = (
                sorted(search_result_schema, key=lambda x: x.get("order", 999)) if search_result_schema else []
            )
            return (
                await self._build_submission_search_payloads(
                    submissions, intake_class, display_fields_sorted, session
                ),
                total_items,
            )

    async def get_tab_records(
        self,
        submission_id: str,
        tab_id: str,
        data_policies: list[dict] | None = None,
    ) -> list[SectionPayloadResponseItem]:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            submission = await self._ensure_submission_readable(
                submission_id, data_policies, session
            )

            tab = await session.get(G2PIntakeFormUITab, tab_id)
            if not tab or tab.form_id != submission.form_id:
                self._invalid_request(
                    f"Tab '{tab_id}' is not part of form '{submission.form_id}'"
                )

            result = await session.execute(
                select(G2PRegisterSection, G2PIntakeFormUITabSection.section_order)
                .join(
                    G2PIntakeFormUITabSection,
                    G2PRegisterSection.section_id == G2PIntakeFormUITabSection.section_id,
                )
                .where(
                    G2PIntakeFormUITabSection.tab_id == tab_id,
                )
                .order_by(G2PIntakeFormUITabSection.section_order.asc())
            )
            sections = result.all()

            documents_by_section = await self._get_submission_documents(submission_id, session)

            response_items: list[SectionPayloadResponseItem] = []
            for section, section_order in sections:
                _register_definition, intake_class, _register_class, _schema_class, _history_class = (
                    await self._resolve_submission_models(section.section_register_id, session)
                )

                row_filters = list(
                    self._submission_section_filters(
                        intake_class,
                        submission_id,
                        section.section_id,
                    )
                )
                policy_condition = await self._build_intake_policy_condition(
                    section.section_register_id,
                    intake_class,
                    data_policies,
                    session,
                )
                if policy_condition is not None:
                    row_filters.append(policy_condition)

                rows = (
                    await session.execute(select(intake_class).where(*row_filters))
                ).scalars().all()

                if not rows and not documents_by_section.get(section.section_id):
                    continue

                response_items.append(
                    SectionPayloadResponseItem(
                        section_id=section.section_id,
                        section_register_id=section.section_register_id,
                        is_list=section.is_list,
                        section_order=section_order,
                        records=[
                            self._serialize_model(row, {"submission_id", "section_id"})
                            for row in rows
                        ],
                        documents=documents_by_section.get(section.section_id),
                    )
                )

            return response_items

    async def process_submission_register_ingest(self, submission_id: str) -> None:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            try:
                async with session.begin():
                    submission = await self._get_submission_or_error(submission_id, session)
                    self._ensure_submission_state(
                        submission,
                        allowed_draft_status={IntakeFormStatusEnum.FINAL.value},
                        message=f"Submission '{submission_id}' must be FINAL before register ingest",
                    )
                    if submission.approval_status != ApprovalStatusEnum.APPROVED.value:
                        self._invalid_request(
                            f"Submission '{submission_id}' must be APPROVED before register ingest"
                        )
                    if submission.register_ingest_process_status not in {
                        ProcessStatusEnum.PENDING.value,
                        ProcessStatusEnum.PROCESSING.value,
                    }:
                        self._invalid_request(
                            f"Submission '{submission_id}' is not ready for register ingest"
                        )
                    sections = await self._get_form_sections(submission.form_id, session)
                    documents_by_section = await self._get_submission_documents(submission_id, session)
                    subject_internal_record_id = await self._resolve_submission_subject_internal_record_id(
                        submission, sections, session
                    )

                    for section in sections:
                        (
                            register_definition,
                            intake_class,
                            register_class,
                            schema_class,
                            history_class,
                        ) = await self._resolve_submission_models(section.section_register_id, session)

                        intake_rows = (
                            await session.execute(
                                select(intake_class).where(
                                    *self._submission_section_filters(
                                        intake_class,
                                        submission.submission_id,
                                        section.section_id,
                                    )
                                )
                            )
                        ).scalars().all()

                        ingested_rows = []
                        for intake_row in intake_rows:
                            live_row = await self._insert_live_register_row(
                                submission,
                                section,
                                register_definition,
                                schema_class,
                                register_class,
                                intake_row,
                                session,
                            )
                            row_subject_id = subject_internal_record_id or (
                                live_row.internal_record_id
                                if section.section_register_id == submission.register_id
                                else None
                            )
                            await self._insert_history_row(
                                submission,
                                section,
                                history_class,
                                live_row,
                                session,
                                subject_internal_record_id=row_subject_id,
                            )
                            ingested_rows.append(live_row)

                        if documents_by_section.get(section.section_id):
                            for live_row in ingested_rows:
                                await self._upsert_live_documents(
                                    submission,
                                    section,
                                    live_row.internal_record_id,
                                    documents_by_section[section.section_id],
                                    session,
                                )

                    submission.register_ingest_process_status = ProcessStatusEnum.PROCESSED.value
                    submission.register_ingest_processed_timestamp = datetime.now()
                    submission.register_ingest_process_attempts = (
                        submission.register_ingest_process_attempts or 0
                    ) + 1
                    submission.register_ingest_process_last_error_code = None
                    session.add(submission)
            except Exception as error:
                _logger.error("Error while ingesting submission %s: %s", submission_id, error)
                await session.rollback()

                async with session_maker() as failure_session:
                    async with failure_session.begin():
                        submission = await failure_session.get(G2PIntakeFormSubmission, submission_id)
                        if submission:
                            submission.register_ingest_process_attempts = (
                                submission.register_ingest_process_attempts or 0
                            ) + 1
                            submission.register_ingest_processed_timestamp = datetime.now()
                            submission.register_ingest_process_last_error_code = str(error)
                            submission.register_ingest_process_status = ProcessStatusEnum.PENDING.value
                            failure_session.add(submission)
                raise

    async def _replace_submission_sections(
        self,
        submission: G2PIntakeFormSubmission,
        section_payloads: list[SectionPayloadInput],
        actor_name: str,
        session,
    ) -> None:
        link_service = G2PIntakeFormLinkService.get_component()
        pending_links: list[tuple] = []
        section_map = {
            section.section_id: section
            for section in await self._get_form_sections(submission.form_id, session)
        }
        for section_payload in section_payloads or []:
            section = section_map.get(section_payload.section_id)
            if not section:
                self._invalid_request(
                    f"Section '{section_payload.section_id}' is not linked to form '{submission.form_id}'"
                )

            register_definition, intake_class, _register_class, schema_class, _history_class = (
                await self._resolve_submission_models(section.section_register_id, session)
            )
            section_has_link_column = link_service.intake_model_has_link_column(intake_class)

            existing_rows = (
                await session.execute(
                    select(intake_class).where(
                        *self._submission_section_filters(
                            intake_class,
                            submission.submission_id,
                            section.section_id,
                        )
                    )
                )
            ).scalars().all()
            for row in existing_rows:
                await session.delete(row)

            for payload_record in section_payload.intake_form_section_payload or []:
                intake_record = dict(payload_record or {})
                action = intake_record.get("edit_action", "ADD")
                if action != "ADD":
                    self._invalid_request("Intake-form submissions only support ADD payload records")

                intake_record["internal_record_id"] = (
                    intake_record.get("internal_record_id") or str(uuid.uuid4())
                )
                schema_instance = schema_class(**intake_record)
                record_data = self._build_record_data(
                    schema_instance.model_dump(),
                    intake_record,
                    intake_class,
                )
                self._stamp_submission_row_fields(record_data, submission)
                self._set_data_if_column(record_data, intake_class, "section_id", section.section_id)
                self._set_data_if_column(record_data, intake_class, "created_by", submission.created_by)
                self._set_data_if_column(
                    record_data,
                    intake_class,
                    "created_at",
                    submission.first_created_at,
                )
                self._set_data_if_column(
                    record_data,
                    intake_class,
                    "last_approved_at",
                    submission.last_updated_at,
                )
                self._set_data_if_column(
                    record_data,
                    intake_class,
                    "last_approved_by",
                    actor_name or submission.created_by,
                )
                new_row = intake_class(**record_data)
                session.add(new_row)
                if section_has_link_column:
                    pending_links.append(
                        (section.section_register_id, intake_record, new_row)
                    )

            await self._upsert_submission_section_documents(
                submission,
                section.section_id,
                section_payload.documents,
                session,
            )

            await session.flush()

        # Second pass: all parent rows are now flushed, so resolve links for
        # every inserted child row regardless of section ordering.
        domain_factory_module = importlib.import_module(
            "openg2p_registry_extensions.register_domain.factory"
        )
        domain_factory = getattr(domain_factory_module, "G2PRegisterDomainFactory").get_component()
        for section_register_id, intake_record, new_row in pending_links:
            resolved_link = await link_service.resolve_link_internal_record_id(
                submission_id=submission.submission_id,
                form_register_id=submission.register_id,
                section_register_id=section_register_id,
                record=intake_record,
                session=session,
                existing_link=None,
                payload_specifies_link="link_internal_record_id" in intake_record,
            )
            new_row.link_internal_record_id = resolved_link
            register_definition = await self._get_register_definition(
                section_register_id, session
            )
            domain_service = domain_factory.get_domain_service(
                register_definition.register_mnemonic
            )
            if domain_service:
                await domain_service.validate_intake_parent_link(
                    intake_record, resolved_link, session
                )
        if pending_links:
            await session.flush()

    async def _build_section_payloads(
        self,
        submission: G2PIntakeFormSubmission,
        session,
    ) -> list[SectionPayloadResponseItem]:
        documents_by_section = await self._get_submission_documents(submission.submission_id, session)
        response_items: list[SectionPayloadResponseItem] = []
        sections = await self._get_form_sections(submission.form_id, session)

        for section in sections:
            _register_definition, intake_class, _register_class, _schema_class, _history_class = (
                await self._resolve_submission_models(section.section_register_id, session)
            )
            rows = (
                await session.execute(
                    select(intake_class).where(
                        *self._submission_section_filters(
                            intake_class,
                            submission.submission_id,
                            section.section_id,
                        )
                    )
                )
            ).scalars().all()
            if not rows and not documents_by_section.get(section.section_id):
                continue

            response_items.append(
                SectionPayloadResponseItem(
                    section_id=section.section_id,
                    section_register_id=section.section_register_id,
                    is_list=section.is_list,
                    records=[
                        self._serialize_model(row, {"submission_id", "section_id"})
                        for row in rows
                    ],
                    documents=documents_by_section.get(section.section_id),
                )
            )

        return response_items

    async def _get_submission_documents(
        self,
        submission_id: str,
        session,
    ) -> dict[str, list]:
        """Map section_id -> attached DocumentData list for a submission."""
        from .g2p_document_service import G2PDocumentService
        from ..schemas import DocumentData

        documents_data = await G2PDocumentService.get_component().get_intake_form_documents_with_session(
            session, submission_id
        )
        documents_by_section: dict[str, list[DocumentData]] = {}
        for doc in documents_data.documents:
            if doc.section_id:
                documents_by_section.setdefault(doc.section_id, []).append(doc)
        return documents_by_section

    async def _count_submission_records(self, submission: G2PIntakeFormSubmission, session) -> int:
        total = 0
        for section in await self._get_form_sections(submission.form_id, session):
            _register_definition, intake_class, _register_class, _schema_class, _history_class = (
                await self._resolve_submission_models(section.section_register_id, session)
            )
            total += (
                await session.execute(
                    select(func.count()).select_from(intake_class).where(
                        *self._submission_section_filters(
                            intake_class,
                            submission.submission_id,
                            section.section_id,
                        )
                    )
                )
            ).scalar_one()
        return total

    async def _delete_submission_rows(self, submission: G2PIntakeFormSubmission, session) -> None:
        sections = await self._get_form_sections(submission.form_id, session)
        for section in sections:
            _register_definition, intake_class, _register_class, _schema_class, _history_class = (
                await self._resolve_submission_models(section.section_register_id, session)
            )
            rows = (
                await session.execute(
                    select(intake_class).where(
                        *self._submission_section_filters(
                            intake_class,
                            submission.submission_id,
                            section.section_id,
                        )
                    )
                )
            ).scalars().all()
            for row in rows:
                await session.delete(row)

        documents = (
            await session.execute(
                select(G2PIntakeFormSubmissionDocument).where(
                    G2PIntakeFormSubmissionDocument.submission_id == submission.submission_id
                )
            )
        ).scalars().all()
        for document in documents:
            await session.delete(document)

        await session.delete(submission)

    async def _insert_live_register_row(
        self,
        submission: G2PIntakeFormSubmission,
        section: G2PRegisterSection,
        register_definition: G2PRegisterDefinition,
        schema_class,
        register_class,
        intake_row,
        session,
    ):
        payload = self._serialize_model(intake_row, {"submission_id", "section_id"})
        schema_instance = schema_class(**payload)
        record_data = self._build_record_data(schema_instance.model_dump(), payload, register_class)
        record_data["created_by"] = submission.created_by
        record_data["created_at"] = submission.first_created_at
        record_data["last_approved_at"] = submission.approved_at or submission.last_updated_at
        record_data["last_approved_by"] = submission.approved_by or "system"

        if (
            register_definition.register_purpose == RegisterPurposeEnum.REGISTER.value
            and register_definition.functional_id_generation_required
            and not record_data.get("functional_record_id")
        ):
            session.add(
                G2PFunctionalIdGenerationQueue(
                    register_id=register_definition.register_id,
                    internal_record_id=record_data["internal_record_id"],
                )
            )
            record_data["functional_record_id"] = f"TEMP-{uuid.uuid4().hex}"

        existing = (
            await session.execute(
                select(register_class).where(
                    register_class.internal_record_id == record_data["internal_record_id"]
                )
            )
        ).scalar_one_or_none()

        if existing:
            await self._update_existing_record(existing, record_data, register_class)
            row = existing
        else:
            row = register_class(**record_data)
            session.add(row)

        await session.flush()
        return row

    async def _resolve_submission_subject_internal_record_id(
        self,
        submission: G2PIntakeFormSubmission,
        sections: list,
        session,
    ) -> str | None:
        """Resolve the master subject internal_record_id for this intake submission."""
        primary_sections = [
            section for section in sections if section.section_register_id == submission.register_id
        ]
        for section in primary_sections:
            _register_definition, intake_class, _register_class, _schema_class, _history_class = (
                await self._resolve_submission_models(section.section_register_id, session)
            )
            intake_rows = (
                await session.execute(
                    select(intake_class).where(
                        *self._submission_section_filters(
                            intake_class,
                            submission.submission_id,
                            section.section_id,
                        )
                    )
                )
            ).scalars().all()
            if not intake_rows:
                continue
            if len(intake_rows) > 1:
                _logger.warning(
                    "Submission %s has %s primary-section intake rows; using the first as subject",
                    submission.submission_id,
                    len(intake_rows),
                )
            return getattr(intake_rows[0], "internal_record_id", None)

        _logger.warning(
            "Could not resolve subject_internal_record_id for submission %s",
            submission.submission_id,
        )
        return None

    async def _insert_history_row(
        self,
        submission: G2PIntakeFormSubmission,
        section: G2PRegisterSection,
        history_class,
        live_row,
        session,
        subject_internal_record_id: str | None = None,
    ) -> None:
        history_data = {
            "history_record_id": str(uuid.uuid4()),
            "internal_record_id": live_row.internal_record_id,
            "tab_id": submission.form_id,
            "section_id": section.section_id,
            "change_request_id": None,
            "submission_id": submission.submission_id,
            "change_request_source": ChangeRequestSourceEnum.INTAKE_FORM.value,
            "is_primary_section": section.section_register_id == submission.register_id,
            "created_by": submission.created_by,
            "created_at": submission.first_created_at,
            "approved_by": submission.approved_by or "system",
            "approved_at": submission.approved_at or submission.last_updated_at,
        }
        if (
            subject_internal_record_id
            and "subject_internal_record_id" in inspect(history_class).columns
        ):
            history_data["subject_internal_record_id"] = subject_internal_record_id
        for key, value in self._serialize_model(live_row).items():
            if key in inspect(history_class).columns and key not in history_data:
                history_data[key] = value

        history_data = self._convert_date_strings_to_objects(history_data, history_class)
        session.add(history_class(**history_data))

    async def _upsert_live_documents(
        self,
        submission: G2PIntakeFormSubmission,
        section: G2PRegisterSection,
        internal_record_id: str,
        documents: list,
        session,
    ) -> None:
        for doc in documents:
            document_id = doc.document_id if hasattr(doc, "document_id") else doc[0]
            label = doc.label if hasattr(doc, "label") else doc[1]
            session.add(
                G2PRegisterDocumentHistory(
                    internal_record_id=internal_record_id,
                    change_request_id=None,
                    submission_id=submission.submission_id,
                    change_request_source=ChangeRequestSourceEnum.INTAKE_FORM.value,
                    section_id=section.section_id,
                    document_id=document_id,
                    label=label,
                    created_by=submission.created_by,
                    created_at=submission.first_created_at,
                    approved_by=submission.approved_by or "system",
                    approved_at=submission.approved_at or submission.last_updated_at,
                )
            )

            existing = (
                await session.execute(
                    select(G2PRegisterSectionDocument).where(
                        G2PRegisterSectionDocument.internal_record_id == internal_record_id,
                        G2PRegisterSectionDocument.document_id == document_id,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.section_id = section.section_id
                existing.label = label
            else:
                session.add(
                    G2PRegisterSectionDocument(
                        internal_record_id=internal_record_id,
                        document_id=document_id,
                        section_id=section.section_id,
                        label=label,
                    )
                )

    async def _resolve_submission_models(self, register_id: str, session):
        register_definition = await self._get_register_definition(register_id, session)
        model_module = importlib.import_module(_DOMAIN_MODELS_MODULE)
        schema_module = importlib.import_module(_DOMAIN_SCHEMAS_MODULE)
        register_mnemonic = register_definition.register_mnemonic
        intake_class = getattr(model_module, f"G2PIntakeForm{register_mnemonic}")
        register_class = getattr(model_module, f"G2PRegister{register_mnemonic}")
        history_class = getattr(model_module, f"G2PRegisterHistory{register_mnemonic}")
        schema_class = getattr(schema_module, f"G2PRegisterSchema{register_mnemonic}")
        return register_definition, intake_class, register_class, schema_class, history_class

    async def _validate_form(self, form_id: str, register_id: str | None, session) -> G2PIntakeFormDefinition:
        intake_form = await session.get(G2PIntakeFormDefinition, form_id)
        if not intake_form:
            self._invalid_request(f"Intake form '{form_id}' was not found")
        if register_id and intake_form.register_id != register_id:
            self._invalid_request(
                f"Intake form '{form_id}' does not belong to register '{register_id}'"
            )
        return intake_form

    async def _get_form_sections(self, form_id: str, session) -> list[G2PRegisterSection]:
        rows = (
            await session.execute(
                select(G2PRegisterSection)
                .join(
                    G2PIntakeFormUITabSection,
                    G2PRegisterSection.section_id == G2PIntakeFormUITabSection.section_id,
                )
                .join(
                    G2PIntakeFormUITab,
                    G2PIntakeFormUITabSection.tab_id == G2PIntakeFormUITab.tab_id,
                )
                .where(G2PIntakeFormUITab.form_id == form_id)
                .order_by(
                    G2PIntakeFormUITab.tab_order.asc(),
                    G2PIntakeFormUITabSection.section_order.asc(),
                    G2PRegisterSection.section_id.asc(),
                )
            )
        ).scalars().all()
        return rows

    async def _get_form_verification_requirement(self, form_id: str, session) -> int:
        result = await session.execute(
            select(G2PIntakeFormDefinition.number_of_verifications).where(
                G2PIntakeFormDefinition.form_id == form_id
            )
        )
        return result.scalar_one_or_none() or 0

    async def _get_register_definition(self, register_id: str, session) -> G2PRegisterDefinition:
        register_definition = await session.get(G2PRegisterDefinition, register_id)
        if not register_definition:
            raise G2PRegistryException(
                code=G2PRegistryErrorCodes.REGISTER_NOT_FOUND.value[1],
                message=G2PRegistryErrorCodes.REGISTER_NOT_FOUND.value[0],
            )
        return register_definition

    async def _get_submission_or_error(self, submission_id: str, session) -> G2PIntakeFormSubmission:
        submission = await session.get(G2PIntakeFormSubmission, submission_id)
        if not submission:
            raise G2PRegistryException(
                code=G2PRegistryErrorCodes.INTAKE_FORM_NOT_FOUND.value[1],
                message=f"{G2PRegistryErrorCodes.INTAKE_FORM_NOT_FOUND.value[0]}: {submission_id}",
            )
        return submission

    def _build_intake_policy_condition(
        self,
        register_id: str,
        intake_class,
        data_policies: list[dict] | None,
        session: AsyncSession,
    ):
        """Resolve REGISTER_RECORD policy and translate it for a G2PIntakeForm* model."""
        if not data_policies:
            return None

        merged_expression = DataPolicyHelper.resolve_register_record_policy(
            data_policies, register_id
        )
        if not merged_expression:
            return None

        return RegisterRecordRepository(intake_class).build_policy_condition(merged_expression)

    async def _ensure_submission_readable(
        self,
        submission_id: str,
        data_policies: list[dict] | None,
        session: AsyncSession,
    ) -> G2PIntakeFormSubmission:
        """Raise if the submission is missing or its intake rows are blocked by data policy."""
        submission = await self._get_submission_or_error(submission_id, session)
        intake_class = await self._resolve_intake_form_class(submission.register_id, session)
        policy_condition = await self._build_intake_policy_condition(
            submission.register_id,
            intake_class,
            data_policies,
            session,
        )
        if policy_condition is None:
            return submission

        readable_row = (
            await session.execute(
                select(intake_class).where(
                    intake_class.submission_id == submission_id,
                    policy_condition,
                )
            )
        ).scalar()
        if readable_row is not None:
            return submission

        any_row = (
            await session.execute(
                select(intake_class).where(intake_class.submission_id == submission_id)
            )
        ).scalar()
        if any_row is not None:
            raise G2PRegistryException(
                code=G2PRegistryErrorCodes.RECORD_ACCESS_DENIED.value[1],
                message=G2PRegistryErrorCodes.RECORD_ACCESS_DENIED.value[0],
            )

        return submission

    async def _build_submission_summary_policy_condition(
        self,
        data_policies: list[dict] | None,
        session: AsyncSession,
    ):
        """OR across registers: submission visible when its intake rows pass that register's policy."""
        if not data_policies:
            return None

        register_definitions = (
            await session.execute(select(G2PRegisterDefinition))
        ).scalars().all()
        if not register_definitions:
            return None

        model_module = importlib.import_module(_DOMAIN_MODELS_MODULE)
        register_clauses = []

        for register_definition in register_definitions:
            try:
                intake_class = getattr(
                    model_module,
                    f"{_INTAKE_CLASS_PREFIX}{register_definition.register_mnemonic}",
                )
            except AttributeError:
                _logger.warning(
                    "Could not resolve intake form model for mnemonic %s; excluding from submission summary",
                    register_definition.register_mnemonic,
                )
                continue

            policy_condition = await self._build_intake_policy_condition(
                register_definition.register_id,
                intake_class,
                data_policies,
                session,
            )

            if policy_condition is not None:
                readable_submission = exists(
                    select(1).select_from(intake_class).where(
                        intake_class.submission_id == G2PIntakeFormSubmission.submission_id,
                        policy_condition,
                    )
                )
                register_clauses.append(
                    and_(
                        G2PIntakeFormSubmission.register_id == register_definition.register_id,
                        readable_submission,
                    )
                )
            else:
                register_clauses.append(
                    G2PIntakeFormSubmission.register_id == register_definition.register_id
                )

        if not register_clauses:
            return None
        return or_(*register_clauses)

    def _ensure_submission_state(
        self,
        submission: G2PIntakeFormSubmission,
        allowed_draft_status: set[str],
        message: str,
    ) -> None:
        if submission.draft_status not in allowed_draft_status:
            raise G2PRegistryException(
                code=G2PRegistryErrorCodes.INTAKE_FORM_INVALID_STATE.value[1],
                message=message,
            )

    def _normalize_submission_source(self, source: str) -> str:
        try:
            return SubmissionSourceEnum(source).value
        except ValueError:
            self._invalid_request(f"Unsupported submission_source '{source}'")

    def _build_submission_response_payload(
        self,
        submission: G2PIntakeFormSubmission,
        section_payloads: list[SectionPayloadResponseItem] | None,
        record_name: str | None,
    ) -> SubmissionResponsePayload:
        return SubmissionResponsePayload(
            submission_id=submission.submission_id,
            application_reference=submission.application_reference,
            record_name=record_name,
            form_id=submission.form_id,
            register_id=submission.register_id,
            draft_status=submission.draft_status,
            number_of_verifications_required=submission.number_of_verifications_required,
            number_of_verifications_done=submission.number_of_verifications_done,
            approval_status=submission.approval_status,
            approved_by=submission.approved_by,
            approved_at=submission.approved_at.isoformat() if submission.approved_at else None,
            finalized_at=submission.finalized_at.isoformat() if submission.finalized_at else None,
            submission_source=submission.submission_source,
            partner_id=submission.partner_id,
            register_ingest_process_status=submission.register_ingest_process_status,
            register_ingest_processed_timestamp=(
                submission.register_ingest_processed_timestamp.isoformat()
                if submission.register_ingest_processed_timestamp
                else None
            ),
            register_ingest_process_attempts=submission.register_ingest_process_attempts,
            register_ingest_process_last_error_code=submission.register_ingest_process_last_error_code,
            created_by=submission.created_by,
            first_created_at=submission.first_created_at.isoformat() if submission.first_created_at else None,
            last_updated_at=submission.last_updated_at.isoformat() if submission.last_updated_at else None,
            awe_request_id=submission.awe_request_id,
            awe_request_status_summary=submission.awe_request_status_summary,
            section_payloads=section_payloads,
        )

    def _extract_record_name(self, sections: list[SectionPayloadResponseItem]) -> str | None:
        for section in sections:
            for record in section.records or []:
                if record.get("record_name"):
                    return record["record_name"]
        return None

    def _apply_submission_filters(
        self,
        query,
        form_id: str | None,
        register_id: str | None,
        draft_status: str | None,
        approval_status: str | None,
        submission_source: str | None,
        partner_id: str | None,
    ):
        if form_id:
            query = query.where(G2PIntakeFormSubmission.form_id == form_id)
        if register_id:
            query = query.where(G2PIntakeFormSubmission.register_id == register_id)
        if draft_status:
            query = query.where(G2PIntakeFormSubmission.draft_status == draft_status)
        if approval_status:
            query = query.where(G2PIntakeFormSubmission.approval_status == approval_status)
        if submission_source:
            query = query.where(
                G2PIntakeFormSubmission.submission_source == self._normalize_submission_source(submission_source)
            )
        if partner_id:
            query = query.where(G2PIntakeFormSubmission.partner_id == partner_id)
        return query

    def _apply_submission_sort(self, query, sort_by: str | None):
        if not sort_by:
            return query.order_by(G2PIntakeFormSubmission.last_updated_at.desc())

        sort_field = sort_by.lstrip("-")
        if not hasattr(G2PIntakeFormSubmission, sort_field):
            return query.order_by(G2PIntakeFormSubmission.last_updated_at.desc())

        sort_column = getattr(G2PIntakeFormSubmission, sort_field)
        return query.order_by(sort_column.desc() if sort_by.startswith("-") else sort_column.asc())

    def _apply_pagination(self, query, current_page: int, page_size: int):
        return query.offset((current_page - 1) * page_size).limit(page_size)

    def _stamp_submission_row_fields(
        self,
        record_data: dict,
        submission: G2PIntakeFormSubmission,
    ) -> None:
        record_data["submission_id"] = submission.submission_id
        record_data["application_reference"] = submission.application_reference

    def _build_record_data(self, schema_data: dict, payload_data: dict, model_class) -> dict:
        mapper = inspect(model_class)
        record_data = {
            key: value
            for key, value in schema_data.items()
            if value is not None and key in mapper.columns and key != "edit_action"
        }
        for key, value in payload_data.items():
            if key in mapper.columns and key not in record_data and key != "edit_action":
                record_data[key] = value
        return self._convert_date_strings_to_objects(record_data, model_class)

    async def _update_existing_record(self, existing, record_data: dict, model_class, session=None) -> None:
        mapper = inspect(model_class)
        for key, value in record_data.items():
            if key in {"internal_record_id", "submission_id", "section_id"} or key not in mapper.columns:
                continue
            setattr(existing, key, self._normalize_model_value(value, key, mapper))

    def _normalize_model_value(self, value, key: str, mapper):
        if value is None or key not in mapper.columns:
            return value
        column = mapper.columns[key]
        if isinstance(column.type, SQLDate):
            if isinstance(value, str):
                if not value.strip():
                    return None
                try:
                    return datetime.strptime(value, "%Y-%m-%d").date()
                except (TypeError, ValueError):
                    return value
            if isinstance(value, datetime):
                return value.date()
        return value

    def _convert_date_strings_to_objects(self, data_dict: dict, model_class) -> dict:
        mapper = inspect(model_class)
        converted = data_dict.copy()
        for key, value in converted.items():
            if value is None or key not in mapper.columns:
                continue
            column = mapper.columns[key]
            if isinstance(column.type, SQLDate):
                if isinstance(value, str):
                    if not value.strip():
                        converted[key] = None
                        continue
                    try:
                        converted[key] = datetime.strptime(value, "%Y-%m-%d").date()
                    except (TypeError, ValueError):
                        pass
                elif isinstance(value, datetime):
                    converted[key] = value.date()
        return converted

    def _set_data_if_column(self, record_data: dict, model_class, column_name: str, value) -> None:
        if column_name in inspect(model_class).columns:
            record_data[column_name] = value

    def _submission_section_filters(self, intake_class, submission_id: str, section_id: str):
        filters = [intake_class.submission_id == submission_id]
        if "section_id" in inspect(intake_class).columns:
            filters.append(intake_class.section_id == section_id)
        return filters

    def _serialize_model(self, row, exclude: set[str] | None = None) -> dict:
        exclude = exclude or set()
        return {
            column.name: getattr(row, column.name)
            for column in inspect(row.__class__).columns
            if column.name not in exclude
        }

    def _invalid_request(self, message: str):
        raise G2PRegistryException(
            code=G2PRegistryErrorCodes.REQUEST_VALIDATION_ERROR.value[1],
            message=message,
        )

    async def get_deduplication_intake_form_register_results(
        self,
        submission_id: str,
    ) -> list[DeduplicationIntakeFormRegisterResultData]:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            rows = (
                await session.execute(
                    select(DeduplicationIntakeFormRegisterResult, G2PRegisterDefinition)
                    .join(
                        G2PRegisterDefinition,
                        G2PRegisterDefinition.register_id == DeduplicationIntakeFormRegisterResult.section_register_id,
                        isouter=True,
                    )
                    .where(DeduplicationIntakeFormRegisterResult.submission_id == submission_id)
                )
            ).all()

            return [
                DeduplicationIntakeFormRegisterResultData(
                    dedup_result_id=r.dedup_result_id,
                    submission_id=r.submission_id,
                    section_register_id=r.section_register_id,
                    section_register_mnemonic=rd.register_mnemonic if rd else None,
                    internal_record_id=r.internal_record_id,
                    match_score=r.match_score,
                    field_matches=r.field_matches,
                    created_at=r.created_at.isoformat() if r.created_at else None,
                )
                for r, rd in rows
            ]

    async def get_deduplication_intake_form_intake_form_results(
        self,
        submission_id: str,
    ) -> list[DeduplicationIntakeFormIntakeFormResultData]:
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            rows = (
                await session.execute(
                    select(DeduplicationIntakeFormIntakeFormResult, G2PRegisterDefinition)
                    .join(
                        G2PRegisterDefinition,
                        G2PRegisterDefinition.register_id == DeduplicationIntakeFormIntakeFormResult.section_register_id,
                        isouter=True,
                    )
                    .where(DeduplicationIntakeFormIntakeFormResult.submission_id == submission_id)
                )
            ).all()

            return [
                DeduplicationIntakeFormIntakeFormResultData(
                    dedup_result_id=r.dedup_result_id,
                    submission_id=r.submission_id,
                    section_register_id=r.section_register_id,
                    section_register_mnemonic=rd.register_mnemonic if rd else None,
                    candidate_submission_id=r.candidate_submission_id,
                    match_score=r.match_score,
                    field_matches=r.field_matches,
                    created_at=r.created_at.isoformat() if r.created_at else None,
                )
                for r, rd in rows
            ]

    async def get_intake_form_submissions_summary(
        self,
        data_policies: list[dict] | None = None,
    ) -> IntakeFormSubmissionsSummaryData:
        """Fetch aggregate summary counts for intake form submissions."""
        session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with session_maker() as session:
            summary_query = select(
                func.count().label("total_submissions"),
                func.sum(
                    case((G2PIntakeFormSubmission.draft_status == IntakeFormStatusEnum.DRAFT.value, 1), else_=0)
                ).label("total_draft_submissions"),
                func.sum(
                    case((G2PIntakeFormSubmission.draft_status == IntakeFormStatusEnum.FINAL.value, 1), else_=0)
                ).label("total_final_submissions"),
                func.sum(
                    case(
                        (
                            (G2PIntakeFormSubmission.draft_status == IntakeFormStatusEnum.FINAL.value) &
                            (G2PIntakeFormSubmission.approval_status == ApprovalStatusEnum.PENDING.value),
                            1,
                        ),
                        else_=0,
                    )
                ).label("total_approval_pending_submissions"),
                func.sum(
                    case((G2PIntakeFormSubmission.register_ingest_process_status == ProcessStatusEnum.PROCESSED, 1), else_=0)
                ).label("total_ingested_submissions"),
                func.sum(
                    case((G2PIntakeFormSubmission.approval_status == ApprovalStatusEnum.APPROVED.value, 1), else_=0)
                ).label("total_approved_submissions"),
                func.sum(
                    case((G2PIntakeFormSubmission.approval_status == ApprovalStatusEnum.REJECTED.value, 1), else_=0)
                ).label("total_rejected_submissions"),
            ).select_from(G2PIntakeFormSubmission)

            policy_condition = await self._build_submission_summary_policy_condition(
                data_policies, session
            )
            if policy_condition is not None:
                summary_query = summary_query.where(policy_condition)

            row = (await session.execute(summary_query)).one()
            return IntakeFormSubmissionsSummaryData(
                total_submissions=row.total_submissions or 0,
                total_draft_submissions=row.total_draft_submissions or 0,
                total_final_submissions=row.total_final_submissions or 0,
                total_approval_pending_submissions=row.total_approval_pending_submissions or 0,
                total_ingested_submissions=row.total_ingested_submissions or 0,
                total_approved_submissions=row.total_approved_submissions or 0,
                total_rejected_submissions=row.total_rejected_submissions or 0,
            )
