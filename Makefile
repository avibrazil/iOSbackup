pkg:
	-rm dist/*
	python3 setup.py sdist bdist_wheel

pypi-test:
	python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

pypi:
	python3 -m twine upload dist/*

changelog:
	f1=`mktemp`; \
	f2=`mktemp`; \
	git tag --sort=-committerdate | tee "$$f1" | sed -e 1d > "$$f2"; \
	paste "$$f1" "$$f2" | sed -e 's|	|...|g' | while read range; do echo; echo "## $$range"; git log '--pretty=format:* %s' "$$range"; done; \
	rm "$$f1" "$$f2"