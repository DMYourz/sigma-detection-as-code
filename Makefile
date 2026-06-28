.PHONY: install dev validate test convert coverage lint clean

install:        ## Install the package
	pip install .

dev:            ## Install with dev extras
	pip install -e ".[dev]"

validate:       ## Structurally validate all Sigma rules
	python -m sigmatools validate

test:           ## Run the test suite (matcher + validation + detection regression)
	pytest -q

convert:        ## Compile rules to Splunk SPL -> generated/splunk/
	python -m sigmatools convert

coverage:       ## Write the MITRE ATT&CK Navigator layer
	python -m sigmatools coverage

lint:           ## Static lint
	ruff check sigmatools tests

clean:
	rm -rf .pytest_cache **/__pycache__ build *.egg-info
