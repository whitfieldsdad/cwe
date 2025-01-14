data:
	pipx run poetry run tool download data/cwec_latest.xml
	pipx run poetry run tool convert data/cwec_latest.xml data/cwec_latest.json

.PHONY: data