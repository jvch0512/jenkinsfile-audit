test:
	groovy -cp src tests/tests.groovy

sample:
	mkdir -p docs site
	bin/jenkinsfile-audit examples 2>/dev/null > docs/sample-output.txt; true
	bin/jenkinsfile-audit examples --tsv 2>/dev/null > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "jenkinsfile-audit" "Audits Jenkinsfiles for secret leaks, shell injection, privileged containers, floating shared libraries and disabled TLS checks. Groovy." "Synthetic Jenkinsfiles."
