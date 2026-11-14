OCAMLOPT ?= ocamlopt

build:
	mkdir -p _build && cp src/*.ml _build/ && cd _build && $(OCAMLOPT) json.ml lint.ml main.ml -o ../iam-policy-lint

test:
	mkdir -p _build && cp src/json.ml src/lint.ml tests/test.ml _build/ && cd _build && $(OCAMLOPT) json.ml lint.ml test.ml -o ../tests/run
	./tests/run

sample: build
	./iam-policy-lint examples/policies > docs/sample-output.txt
	./iam-policy-lint examples/policies --html > site/index.html
