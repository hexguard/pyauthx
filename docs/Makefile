SPHINXOPTS ?=
SPHINXBUILD ?= sphinx-build 
SOURCEDIR = source 
BUILDDIR = build 
AUTODOCDIR = souce/api 
EXAMPLESDIR = source/examples

%: Makefile 
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

clean:
	rm -rf $(BUILDDIR)/*
	rm -rf $(AUTODOCDIR)/*
	rm -rf $(EXAMPLESDIR)/*.rst 
	rm -rf .doctrees

readthedocs: html 
default: html

