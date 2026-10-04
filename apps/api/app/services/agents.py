"""Named evidence-only investigation agents."""

from sqlalchemy.orm import Session

from app.models.investigation import Investigation
from app.services.ai_investigation import run_agent


class HeaderAgent:
    name = "header"

    def run(self, db: Session, investigation: Investigation):
        return run_agent(db, investigation, self.name)[0]


class URLAgent:
    name = "url"

    def run(self, db: Session, investigation: Investigation):
        return run_agent(db, investigation, self.name)[0]


class ContentSocialEngineeringAgent:
    name = "content"

    def run(self, db: Session, investigation: Investigation):
        return run_agent(db, investigation, self.name)[0]


class CorrelationAgent:
    name = "correlation"

    def run(self, db: Session, investigation: Investigation):
        return run_agent(db, investigation, self.name)[0]


class ReportAgent:
    name = "report"

    def run(self, db: Session, investigation: Investigation):
        return run_agent(db, investigation, self.name)[0]
