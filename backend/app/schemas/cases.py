from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    HOLD = "HOLD"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CONFIRMED_FRAUD = "CONFIRMED_FRAUD"


OPEN_STATUSES = {CaseStatus.NEW.value, CaseStatus.INVESTIGATING.value, CaseStatus.HOLD.value}


class AnalystAction(str, Enum):
    HOLD = "HOLD"
    STEP_UP = "STEP_UP"
    BLOCK = "BLOCK"
    INVESTIGATE = "INVESTIGATE"
    MARK_LEGITIMATE = "MARK_LEGITIMATE"
    CONFIRM_FRAUD = "CONFIRM_FRAUD"
    RESOLVE = "RESOLVE"
    COMMENT = "COMMENT"


# analyst action -> resulting case status (None = unchanged)
ACTION_TO_STATUS: dict[str, str | None] = {
    AnalystAction.HOLD.value: CaseStatus.HOLD.value,
    AnalystAction.STEP_UP.value: CaseStatus.INVESTIGATING.value,
    AnalystAction.BLOCK.value: CaseStatus.HOLD.value,
    AnalystAction.INVESTIGATE.value: CaseStatus.INVESTIGATING.value,
    AnalystAction.MARK_LEGITIMATE.value: CaseStatus.FALSE_POSITIVE.value,
    AnalystAction.CONFIRM_FRAUD.value: CaseStatus.CONFIRMED_FRAUD.value,
    AnalystAction.RESOLVE.value: CaseStatus.RESOLVED.value,
    AnalystAction.COMMENT.value: None,
}


class FeedbackIn(BaseModel):
    action: AnalystAction
    analyst: str = Field(default="demo-analyst", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 _.-]+$")
    notes: str = Field(default="", max_length=2000)
