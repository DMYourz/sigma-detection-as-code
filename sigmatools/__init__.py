"""sigma-detection-as-code: author, test, and compile Sigma rules.

Modules:
  matcher  - offline Sigma evaluator (the detection test engine)
  loader   - load rules and their TP/FP test cases
  convert  - compile rules to Splunk SPL via pySigma
  coverage - emit a MITRE ATT&CK Navigator layer from rule tags
  cli      - validate / convert / coverage commands
"""
__version__ = "1.0.0"
