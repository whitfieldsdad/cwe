default: clean data

install:
	poetry install

data:
	mkdir -p data
	poetry run tool download data/cwec_v5.0.xml
	poetry run tool convert data/cwec_v5.0.xml data/mitre-cwe.json

diagrams:
	find . -type f -name "*.dot" -exec sh -c 'dot -Tpng -o "$${1%.dot}.png" "$$1"' _ {} \;

clean:
	find . -type f -name "._*" -delete
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

test:
	poetry run pytest

.PHONY: data diagrams test clean install default
