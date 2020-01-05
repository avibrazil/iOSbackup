pkg:
	python3 setup.py sdist bdist_wheel

pypi-test:
	python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

pypi:
	python3 -m twine upload dist/*
