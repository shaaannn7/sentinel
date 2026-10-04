# Data flow

```text
Browser
  -> FastAPI multipart endpoint
  -> bounded validation and ArtifactStorage
  -> RFC 822 parser
  -> Investigation + Artifact + Header + Attachment + Indicator + Auth + Hop rows
  -> deterministic analyzers (shared parsed representation)
  -> Evidence + Finding + AnalysisStage + TimelineEvent rows
  -> bounded score/verdict and investigation summary
  -> list/detail APIs
  -> optional bounded AI analysis
  -> AIAudit rows and advisory output
```

The UI must render email HTML only as sanitized output and should treat every investigation field as untrusted display data. No extracted URL is fetched automatically. Private, loopback, link-local, reserved, and invalid IPs are never eligible for external lookup.
